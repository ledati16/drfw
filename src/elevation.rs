pub fn create_elevated_nft_command(args: &[&str]) -> tokio::process::Command {
    let mut cmd = tokio::process::Command::new("pkexec");
    cmd.arg("nft").args(args);
    cmd
}
