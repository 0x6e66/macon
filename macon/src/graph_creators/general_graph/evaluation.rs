use std::collections::HashMap;

use crate::graph_creators::general_graph::general::Node;

pub struct ClusterEvaluation {
    pub purity: f64,
    pub nmi: f64,
    pub ri: f64,
    pub f5: f64,
}

pub fn eval_clustering(cluster: &[&[&Node]]) -> ClusterEvaluation {
    let n: usize = cluster.iter().map(|c| c.len()).sum();
    let cluster_distributions: Vec<HashMap<String, usize>> =
        cluster.iter().map(|c| cluster_distribution(c)).collect();
    let label_distribution = label_distribution(cluster);

    let purity = calc_purity(&cluster_distributions, n);
    let nmi = calc_nmi(&cluster_distributions, &label_distribution, n);
    let (ri, f5) = calc_ri_and_f_beta(&cluster_distributions, &label_distribution, 5, n);

    ClusterEvaluation {
        purity,
        nmi,
        ri,
        f5,
    }
}

fn calc_ri_and_f_beta(
    cluster_distributions: &[HashMap<String, usize>],
    label_distribution: &HashMap<String, usize>,
    beta: usize,
    n: usize,
) -> (f64, f64) {
    // TP + FP
    let tp_fp: usize = cluster_distributions
        .iter()
        .map(|dist| {
            let cluster_n = dist.values().sum::<usize>();
            bimon2(cluster_n)
        })
        .sum();

    let tp: usize = cluster_distributions
        .iter()
        .map(|dist| {
            dist.values()
                .filter(|v| **v >= 2)
                .map(|v| bimon2(*v))
                .sum::<usize>()
        })
        .sum();

    // TN + FN
    let tn_fn: usize = cluster_distributions
        .iter()
        .map(|dist| {
            let cluster_n = dist.values().sum::<usize>();
            cluster_n * (n - cluster_n)
        })
        .sum::<usize>()
        / 2;

    let tn: usize = cluster_distributions
        .iter()
        .map(|dist| {
            dist.iter()
                .map(|(k, v)| (label_distribution[k] - v) * v)
                .sum::<usize>()
        })
        .sum::<usize>()
        / 2;

    let ri = (tp + tn) as f64 / (tp_fp + tn_fn) as f64;

    // PPV = TP / (TP + FP)
    let ppv = tp / tp_fp;
    // TPR = TP / (TP + FN) = TP / (TP + TN + FN - TN)
    let recall = tp / (tp + tn_fn - tn);

    let beta_cubed = beta * beta;
    let f_beta = ((beta_cubed + 1) * ppv * recall) as f64 / (beta_cubed * ppv + recall) as f64;

    (ri, f_beta)
}

///   bimon(x,2)
/// = x/2 * bimon(x-1, 1)
/// = x/2 * (x-1) * bimon(x-2, 0)
///
/// with binom(z, 0) = 1:
///
/// = x/2 * (x-1)
/// = (x * x - x) /2
fn bimon2(x: usize) -> usize {
    (x * x - x) / 2
}

fn calc_purity(cluster_distributions: &[HashMap<String, usize>], n: usize) -> f64 {
    cluster_distributions
        .iter()
        .map(|dist| {
            dist.iter()
                .max_by_key(|(_, c)| *c)
                .map(|(_, c)| *c)
                .unwrap_or(0)
        })
        .sum::<usize>() as f64
        / n as f64
}

fn calc_nmi(
    cluster_distributions: &[HashMap<String, usize>],
    label_distribution: &HashMap<String, usize>,
    n: usize,
) -> f64 {
    // H(Y)
    let entropy_class_labels = entropy_class_labels(label_distribution, n);

    // H(C)
    let entropy_cluster_labels = entropy_cluster_labels(cluster_distributions, n);

    // H(Y|C)
    let entropy_class_labels_within_cluster =
        entropy_class_labels_within_cluster(cluster_distributions, n);

    // I(Y; C) = H(Y) - H(Y|C)
    let mutual_information = entropy_class_labels - entropy_class_labels_within_cluster;

    //            2 * I(Y; C)
    // NMI(Y,C) = -----------
    //            H(Y) + H(C)
    2.0 * mutual_information / (entropy_class_labels + entropy_cluster_labels)
}

/// H(Y)
fn entropy_class_labels(label_distribution: &HashMap<String, usize>, n: usize) -> f64 {
    label_distribution
        .values()
        .map(|v| {
            let t = *v as f64 / n as f64;
            -t * f64::log2(t)
        })
        .sum()
}

/// H(C)
fn entropy_cluster_labels(cluster_distributions: &[HashMap<String, usize>], n: usize) -> f64 {
    cluster_distributions
        .iter()
        .map(|dist| dist.values().sum::<usize>())
        .map(|v| {
            let t = v as f64 / n as f64;
            -t * f64::log2(t)
        })
        .sum()
}

/// H(Y|C)
fn entropy_class_labels_within_cluster(
    cluster_distributions: &[HashMap<String, usize>],
    n: usize,
) -> f64 {
    cluster_distributions
        .iter()
        .map(|dist| {
            let cluster_n: f64 = dist.values().sum::<usize>() as f64;
            let f: f64 = dist
                .values()
                .map(|v| {
                    let t = *v as f64 / cluster_n;
                    t * f64::log2(t)
                })
                .sum();

            -(cluster_n / n as f64) * f
        })
        .sum()
}

/// Calculates the distribution of class labels / families inside a cluster of nodes
fn cluster_distribution(nodes: &[&Node]) -> HashMap<String, usize> {
    let mut result = HashMap::new();

    for node in nodes {
        *result.entry(node.family.clone()).or_insert(0) += 1;
    }

    result
}

/// Calculates the distribution of class labels / families inside an entire cluster
fn label_distribution(cluster: &[&[&Node]]) -> HashMap<String, usize> {
    let mut result = HashMap::new();

    for c in cluster {
        for node in *c {
            *result.entry(node.family.clone()).or_insert(0) += 1;
        }
    }

    result
}
