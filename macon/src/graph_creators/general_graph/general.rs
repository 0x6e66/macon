extern crate ssdeep;

use std::{
    collections::HashMap,
    io::{Read, Write},
    path::PathBuf,
    sync::{Arc, Mutex},
};

use anyhow::Result;
use indicatif::ParallelProgressIterator;
use lavinhash::{HashConfig, model::FuzzyFingerprint};
use rayon::iter::{IntoParallelIterator, IntoParallelRefIterator, ParallelIterator};
use sha256::digest;
use smartcore::{
    cluster::{
        dbscan::{DBSCAN, DBSCANParameters},
        kmeans::{KMeans, KMeansParameters},
    },
    linalg::basic::matrix::DenseMatrix,
};

use crate::graph_creators::general_graph::{
    GeneralGraph,
    evaluation::{ClusterEvaluation, eval_clustering},
};

fn get_labeld_files(files: Vec<PathBuf>) -> HashMap<String, Vec<PathBuf>> {
    let mut map: HashMap<String, Vec<PathBuf>> = HashMap::new();

    for file in files {
        let family = file
            .parent()
            .and_then(|path| path.file_name().and_then(|name|name.to_str()))
            .map(|s| s.to_string()).expect("Sample has to be in a directory. The directory name indicates the malware family for evaluation");

        if let Some(paths) = map.get_mut(&family) {
            paths.push(file);
        } else {
            map.insert(family, vec![file]);
        }
    }

    map
}

impl GeneralGraph {
    pub fn general_graph_entry(&self, files: Vec<PathBuf>) -> Result<()> {
        let mut nodes = vec![];

        let labeled_files = get_labeld_files(files);

        for (family, files) in labeled_files {
            let mut tmp_nodes = get_nodes_from_files(files, family)?;
            nodes.append(&mut tmp_nodes);
        }

        // ensure nodes is immutable from here on
        let nodes = nodes;

        // let distance_functions = [ssdeep_distance, lavin_distance, tlsh_distance];
        let mut distance_functions: HashMap<&str, fn(&Node, &Node) -> f64> = HashMap::new();
        distance_functions.insert("ssdeep", ssdeep_distance);
        distance_functions.insert("lavin", lavin_distance);
        distance_functions.insert("tlsh", tlsh_distance);

        for (n, d) in distance_functions {
            let tmp = compute_distance_matrix(&nodes, d);
            let distance_matrix = DenseMatrix::from_2d_vec(&tmp)?;

            let filename = format!("dbscan_{n}.csv");
            let file = Arc::new(Mutex::new(std::fs::File::create(filename)?));

            writeln!(&mut file.lock().unwrap(), "eps,min_pts,prurity,nmi,ri,f5")?;

            (1..100).into_par_iter().progress().for_each(|eps| {
                for min_pts in 1..100 {
                    let labels = get_dbscan_labels(&distance_matrix, eps as f64, min_pts);
                    let cluster = partition_nodes_in_cluster(&labels, &nodes);
                    let c: Vec<&[&Node]> = cluster.iter().map(|d| d.as_slice()).collect();

                    let ClusterEvaluation {
                        purity,
                        nmi,
                        ri,
                        f5,
                    } = eval_clustering(&c);

                    writeln!(
                        &mut file.lock().unwrap(),
                        "{eps},{min_pts},{purity},{nmi},{ri},{f5}",
                    )
                    .unwrap();
                }
            });
        }

        Ok(())
    }
}

#[allow(dead_code)]
fn get_dbscan_labels(distance_matrix: &DenseMatrix<f64>, eps: f64, min_pts: usize) -> Vec<usize> {
    DBSCAN::fit(
        distance_matrix,
        DBSCANParameters::default()
            .with_eps(eps)
            .with_min_samples(min_pts),
    )
    .and_then(|dbscan| dbscan.predict(distance_matrix))
    .unwrap()
}

#[allow(dead_code)]
fn get_kmeans_labels(distance_matrix: &DenseMatrix<f64>, num_clusters: usize) -> Vec<usize> {
    KMeans::fit(
        distance_matrix,
        KMeansParameters::default().with_k(num_clusters),
    )
    .and_then(|kmeans| kmeans.predict(distance_matrix))
    .unwrap()
}

/// Group nodes in their cluster based on the labels from a clustering algorithm
fn partition_nodes_in_cluster<'a>(labels: &[usize], nodes: &'a [Node]) -> Vec<Vec<&'a Node>> {
    assert_eq!(labels.len(), nodes.len());

    let Some(num_clusters) = labels.iter().max().map(|n| n + 1) else {
        return vec![vec![]];
    };

    let mut res = vec![vec![]; num_clusters];

    for (l, n) in labels.iter().zip(nodes) {
        res[*l].push(n);
    }

    res
}

#[derive(Clone, Debug)]
pub struct Node {
    pub sha256sum: String,
    pub ssdeep_hash: String,
    pub lavinhash: FuzzyFingerprint,
    pub tlsh_hash: String,
    pub family: String,
}

/// Calculate the distance matrix between all nodes with a given distance function
/// The distance function has to be symmetric so that d(x,y) == d(y,x)
///
/// The resulting distance matrix will look like this:
///
///        |   a    |   b    |   c    |  ...  
/// -------|--------|--------|--------|------
///    a   |   0    | d(a,b) | d(a,c) |  ...
///    b   | d(b,a) |   0    | d(b,c) |  ...
///    c   | d(c,a) | d(c,b) |   0    |  ...
///   ...  |  ...   |  ...   |  ...   |  ...
fn compute_distance_matrix(
    nodes: &[Node],
    distance_function: fn(a: &Node, b: &Node) -> f64,
) -> Vec<Vec<f64>> {
    let n = nodes.len();
    let mut distance_matrix = vec![vec![0.0; n]; n];

    for i in 0..n {
        for j in i..n {
            if i == j {
                distance_matrix[i][j] = 0.0;
                continue;
            }

            let d = distance_function(&nodes[i], &nodes[j]);
            distance_matrix[i][j] = d;
            distance_matrix[j][i] = d;
        }
    }

    distance_matrix
}

/// Regarding the distance functions:
/// The underlying similarity hashes map from 0 to 100 representing a level of similarity (100 essentially means it is the same file)
/// The distance functions need to represent a distance between each other (0 essentially means it is the same file)
///
/// The similarities are mapped to a negative exponential function so that:
///  a similarity of 0 is mapped to a distance of 100 and
///  a similarity of 100 is mapped to a distance of 0
///
/// Considering a similarity function s that looks like this:
///  sim = s(node_1, node_2)
///
/// The distance function is defined as follows:
///  d(sim) = a ^ (100 - sim) - b with
///      a = 101^(1/100) = 100 * sqrt(101) (approx. 1.0472)
///      b = 1
#[inline(always)]
fn map_similary_to_distance(similarity: f64) -> f64 {
    #[allow(clippy::approx_constant)]
    let a: f64 = 1.0472;
    let b: f64 = 1.0;

    a.powf(100.0 - similarity) - b
}

#[inline(always)]
fn ssdeep_distance(a: &Node, b: &Node) -> f64 {
    let similarity = ssdeep::compare(&a.ssdeep_hash, &b.ssdeep_hash).unwrap() as f64;

    map_similary_to_distance(similarity)
}

#[inline(always)]
fn lavin_distance(a: &Node, b: &Node) -> f64 {
    let similarity = lavinhash::compare_hashes(&a.lavinhash, &b.lavinhash, 0.3) as f64;

    map_similary_to_distance(similarity)
}

#[inline(always)]
fn tlsh_distance(a: &Node, b: &Node) -> f64 {
    tlsh::compare(&a.tlsh_hash, &b.tlsh_hash).unwrap() as f64
}

fn get_nodes_from_files(files: Vec<PathBuf>, family: String) -> Result<Vec<Node>> {
    files
        // .iter()
        // .take(100)
        .par_iter()
        .progress()
        .map(|entry| {
            let mut file = std::fs::File::open(entry)?;

            let mut buf = Vec::new();
            file.read_to_end(&mut buf)?;

            let sha256sum = digest(&buf);
            let ssdeep_hash = ssdeep::hash(&buf)?;

            let lavin_config = HashConfig {
                enable_parallel: false,
                ..Default::default()
            };
            let lavinhash = lavinhash::generate_hash(&buf, &lavin_config)?;

            let tmp = tlsh::hash_buf(&buf)?;
            let tlsh_hash = tmp.to_string();

            Ok(Node {
                sha256sum,
                ssdeep_hash,
                lavinhash,
                tlsh_hash,
                family: family.clone(),
            })
        })
        .collect()
}
