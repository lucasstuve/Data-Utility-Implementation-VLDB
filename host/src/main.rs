use benchmarks::performance_benchmarks::{write_results_csv, Row};
use colored::{ColoredString, Colorize};
use dnf_core::epl::ProgramAst;
use methods::{EVAL_AST_ELF, EVAL_AST_ID};
use std::env;
use std::thread;
use std::time::{Duration, Instant};
use system_core::data_consumer as al_company;
use system_core::data_consumer;
use system_core::manufacturer::{
    self,
    BATCH_JSON_1000MB, BATCH_JSON_100MB, BATCH_JSON_10MB, USER_BATCH_JSON, VW_BATCH_JSON,
};

mod parser;
mod predata_processor;

use predata_processor::create_events_indexes;

fn main() {
    let args: Vec<String> = env::args().collect();
    let dataset_name = match args.get(1) {
        Some(name) => name.as_str(),
        None => {
            eprintln!(
                "Usage: cargo run -p host --release -- <dataset>\n\
                 Example: cargo run -p host --release -- test-data-10-MB.json"
            );
            return;
        }
    };

    let mut bench: Row = Row::new();

    println!(
        "\n{}{}",
        "START DATA UTILITY ATTESTATION PROTOCOL FOR DATASET: ".bold(),
        dataset_name
    );

    // -------------------------------------------------------------------------
    // PHASE I
    // -------------------------------------------------------------------------
    phase("PHASE I: Batch provisioning by the MANUFACTURER");

    step(1, "Manufacturer".red(), "collects the user batch.");

    let data: &str = match dataset_name {
        "vw-batch.json" => &VW_BATCH_JSON,
        "user-batch.json" => &USER_BATCH_JSON,
        "test-data-10-MB.json" => &BATCH_JSON_10MB,
        "test-data-100-MB.json" => &BATCH_JSON_100MB,
        "test-data-1000-MB.json" => &BATCH_JSON_1000MB,
        unknown => {
            eprintln!("Unknown dataset: {unknown}");
            eprintln!(
                "Supported datasets: vw-batch.json, user-batch.json, \
                 test-data-10-MB.json, test-data-100-MB.json, test-data-1000-MB.json"
            );
            std::process::exit(2);
        }
    };

    // For testing, manufacturer-side generation is replaced by controlled data batches.
    // manufacturer::collect_batch(dataset_name, 1);

    let json_batch: serde_json::Value = serde_json::from_str(data).expect("JSON invalid.");
    println!("Loaded JSON batch:");
    println!("{:#?}", json_batch);

    step(2, "Manufacturer".red(), "signs the user batch.");

    let (batch_bytes, pub_key, signature) = manufacturer::sign_batch(dataset_name);

    println!("Signature:");
    println!("{:?}", &signature);

    step(
        3,
        "Manufacturer".red(),
        "ships B_raw, Signature(M), and Pk_m to the USER.",
    );

    // -------------------------------------------------------------------------
    // PHASE II
    // -------------------------------------------------------------------------
    phase("PHASE II: Utility rule generation by the Predictive-Maintenance Company");

    step(
        4,
        "Predictive-Maintenance Company".green(),
        "collects the initial labelled dataset for the AL base model.",
    );

    let data_from_base_model = al_company::base_model_dataset();

    println!("Initial labelled dataset: {:?}", data_from_base_model);

    step(
        5,
        "Predictive-Maintenance Company".green(),
        "trains the decision tree classifier and obtains utility rules.",
    );

    let decision_tree = al_company::train_linfa_decision_tree(data_from_base_model);
    let textual_predicate = al_company::obtain_predicate_from_decision_tree(
        decision_tree,
        "profiles.targetSOCPercentage",
        1usize,
    );

    step(
        6,
        "Predictive-Maintenance Company".green(),
        "generates the query from the predicate rules.",
    );

    let query = al_company::generate_query_from_textual_predicate(&textual_predicate);

    println!("Generated query:");
    println!("{}", query);

    step(
        7,
        "USER".purple(),
        "receives the query and parses the Utility Attestation program.",
    );

    let dnf = user::parse_utility_program(&query);

    let ast: ProgramAst = match dnf {
        Err(e) => {
            println!("Error: {}", e);
            return;
        }
        Ok(tree) => tree,
    };

    println!("{}", "Parsed Abstract Syntax Tree from CPR:".yellow());
    println!("{:#?}", ast);

    // -------------------------------------------------------------------------
    // PHASE III
    // -------------------------------------------------------------------------
    phase("PHASE III: Preprocessing by the USER");

    step(
        8,
        "USER".purple(),
        "computes the list of index pairs from B_raw.",
    );

    let index_list = user::preprocess_batch(&batch_bytes);

    println!("Index list:");
    println!("{:#?}", index_list);

    // -------------------------------------------------------------------------
    // PHASE IV
    // -------------------------------------------------------------------------
    phase("PHASE IV: Proof generation by the USER");

    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::filter::EnvFilter::from_default_env())
        .init();

    step(
        9,
        "USER".purple(),
        "inputs Signature(M), B_raw, AST, IndexList, and Pk_m into the attested computation environment.",
    );

    let env = user::build_attestation_environment(
        &ast,
        &batch_bytes,
        &index_list,
        &pub_key,
        &signature,
    );

    step(
        10,
        "USER".purple(),
        "initiates proof/attestation generation.",
    );

    // generate_attestation measures only the proving operation itself; step()
    // delays and environment construction are intentionally excluded.
    let (prove_info, proving_time) = user::generate_attestation(env, EVAL_AST_ELF);

    let receipt = prove_info.receipt;

    println!("Proof generation completed.");
    println!("Proving time: {:?} s", proving_time);

    step(
        11,
        "USER".purple(),
        "passes the Attestation to the Predictive-Maintenance Company.",
    );

    // -------------------------------------------------------------------------
    // PHASE V
    // -------------------------------------------------------------------------
    phase("PHASE V: Verification by the Predictive-Maintenance Company");

    step(
        12,
        "Predictive-Maintenance Company".green(),
        "verifies the received Attestation.",
    );

    let verify_timer = Instant::now();
    let verified_attestation = al_company::verify_attestation(&receipt, EVAL_AST_ID);
    let verify_attest_time = verify_timer.elapsed().as_millis();

    step(
        13,
        "Predictive-Maintenance Company".green(),
        "extracts the result, commitment of parsed and hashed P, and signature from the Attestation.",
    );

    let (result, attestation_commit, attestation_sig) = verified_attestation;

    println!("Attestation result:");
    println!("Result: {:?}", result);
    println!("Commitment(P): {:?}", attestation_commit);
    println!("Attested signature: {:?}", attestation_sig);

    step(
        14,
        "Predictive-Maintenance Company".green(),
        "recomputes the commitment using the query.",
    );

    let expected_commitment = al_company::recalculate_predicate_hash(&query);

    println!("Recalculated commitment: {:?}", expected_commitment);

    step(
        15,
        "Predictive-Maintenance Company".green(),
        "checks that committed P used for the Attestation matches recomputed P.",
    );

    let commit_holds = al_company::check_commitment(expected_commitment, attestation_commit);

    println!("Commitment holds: {:?}", commit_holds);

    step(
        16,
        "Predictive-Maintenance Company".green(),
        "checks that the signature committed in the Attestation belongs to the Manufacturer.",
    );

    let signature_correctly_used = al_company::check_sig_alignment(signature, attestation_sig);

    println!(
        "Signature belongs to Manufacturer: {}",
        signature_correctly_used
    );

    step(
        17,
        "Predictive-Maintenance Company".green(),
        "recomputes the image ID from the audited program and compares it with the receipt image ID.",
    );

    let recomputed_id = data_consumer::recompute_image_id()
        .expect("Failed to recompute the audited program image ID.");
    let image_id_from_receipt = data_consumer::get_image_id_from_receipt(&receipt);
    let recomputed_id_matches =
        data_consumer::validate_image_id(image_id_from_receipt, recomputed_id);

    println!(
        "ZK-Attestation proof corresponds to the provided receipt: {}",
        recomputed_id_matches
    );

    // -------------------------------------------------------------------------
    // PHASE VI
    // -------------------------------------------------------------------------
    phase("PHASE VI: Final purchase decision");

    step(
        18,
        "Predictive-Maintenance Company".green(),
        "decides whether to buy the data based on the Manufacturer signature, committed P, program image, and evaluation result.",
    );

    if commit_holds && signature_correctly_used && recomputed_id_matches && result {
        println!(
            "{}: requests purchase of the batch B_raw.",
            "Predictive-Maintenance Company".green()
        );
    } else {
        println!(
            "{}: rejects purchase of the batch B_raw.",
            "Predictive-Maintenance Company".green()
        );
    }

    // Benchmark bookkeeping belongs to the protocol run, so write it before END.
    bench.set_dsl_query(dataset_name);
    bench.set_segments(prove_info.stats.segments as u32);
    bench.set_user_cycles(prove_info.stats.user_cycles as u64);
    bench.set_total_cycles(prove_info.stats.total_cycles as u64);
    bench.set_prove_time(proving_time as u32);
    bench.set_veri_time(verify_attest_time as u64);
    bench.set_input_bytes(batch_bytes.len() as u64);

    write_results_csv(vec![bench], "end-to-end-benchmarks.csv").unwrap();

    println!("\n{}\n", "END DATA UTILITY ATTESTATION PROTOCOL".bold());
}


// USER-side protocol actions live locally because the Manufacturer and
// Predictive-Maintenance Company already expose their actions from system_core.
//
// Unlike generic closure wrappers, these functions expose the actual data that
// the USER consumes at each protocol step.
mod user {
    use super::{create_events_indexes, parser};
    use dnf_core::epl::ProgramAst;
    use risc0_zkvm::{default_prover, ExecutorEnv, ProveInfo};
    use serde::Serialize;
    use std::fmt::Debug;
    use std::str;
    use std::time::Instant;

    /// Step 7: USER receives the generated query and parses it into the AST
    /// that will be supplied to the attested computation.
    pub fn parse_utility_program(query: &str) -> Result<ProgramAst, String> {
        parser::parse_source(query).map_err(|error| error.to_string())
    }

    /// Step 8: USER receives B_raw and computes the event index pairs used by
    /// the guest program.
    ///
    /// The concrete index-list type is defined by predata_processor. We expose
    /// the capabilities main() needs from it: Debug for printing and Serialize
    /// for writing it into the zkVM environment.
    pub fn preprocess_batch(
        batch_bytes: &[u8],
    ) -> impl Serialize + Debug {
        let batch_string =
            str::from_utf8(batch_bytes).expect("Batch is not valid UTF-8.");

        create_events_indexes(batch_string)
    }

    /// Step 9: USER constructs the attested-computation environment.
    ///
    /// Protocol inputs are explicit in the function signature:
    ///   - parsed utility program (AST)
    ///   - raw manufacturer batch B_raw
    ///   - preprocessing index list
    ///   - manufacturer public key Pk_m
    ///   - manufacturer signature Signature(M)
    pub fn build_attestation_environment<I>(
        ast: &ProgramAst,
        batch_bytes: &[u8],
        index_list: &I,
        pub_key: &[u8],
        signature: &[u8],
    ) -> ExecutorEnv<'static>
    where
        I: Serialize,
    {
        let file_len: u32 = batch_bytes
            .len()
            .try_into()
            .expect("Batch is too large for the guest input length field.");

        let sig_length: u32 = signature
            .len()
            .try_into()
            .expect("Signature is too large for the guest input length field.");

        ExecutorEnv::builder()
            .write(ast)
            .unwrap()
            .write(&file_len)
            .unwrap()
            .write_slice(batch_bytes)
            .write(index_list)
            .unwrap()
            .write(&(pub_key.len() as u32))
            .unwrap()
            .write_slice(pub_key)
            .write(&(sig_length as usize))
            .unwrap()
            .write_slice(signature)
            .build()
            .unwrap()
    }

    /// Step 10: USER runs the audited guest program and generates the
    /// attestation. The returned duration contains only prover execution time.
    pub fn generate_attestation(
        env: ExecutorEnv<'_>,
        program_elf: &[u8],
    ) -> (ProveInfo, u64) {
        let prover = default_prover();
        let prove_timer = Instant::now();
        let prove_info = prover.prove(env, program_elf).unwrap();
        let proving_time = prove_timer.elapsed().as_secs();

        (prove_info, proving_time)
    }
}

fn separator() {
    println!("\n{}\n", "-".repeat(94));
}

fn phase(title: &str) {
    println!("\n\n{}", "=".repeat(94));
    println!("{}", title);
    println!("{}\n", "=".repeat(94));
}

fn step(number: u32, actor: ColoredString, message: &str) {
    separator();
    println!("({}): {} {}", number, actor, message);
    separator();

    // Presentation delay only. Timers for proving/verification are started after
    // the corresponding step message so this sleep is not part of the benchmark.
    thread::sleep(Duration::from_secs(2));
}
