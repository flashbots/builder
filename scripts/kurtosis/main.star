#Use: kurtosis.exe run  --enclave explorer ./kurtosis/ '{"file_to_read": "./network_params.json"}'
#Node: works only with config files local to ./kurtosis/ folder where kurtosis.yml is defined

eth_pkg = import_module(
    "github.com/kurtosis-tech/ethereum-package/main.star@0.6.1"
)

def run(plan, file_to_read = "network_params_tmp.json"):
    inputs = json.decode(read_file(src=file_to_read))
    plan.print(inputs)
    eth_pkg.run(plan, inputs)
