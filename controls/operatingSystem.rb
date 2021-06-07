mongo_conf_file  = attribute('conf_file', default: '/etc/mongod.conf', description: 'Path to the mongod.conf file')
conf_file = yaml(mongo_conf_file)

control 'mongod-Operating-System-Hardening-1' do
    impact 1.0
    title 'mongod should be running and enabled'
    desc 'mongod should be running and enabled. When system restarts apruptly mongod should be started and loaded automatically'
    tag Vulnerability: 'High'
    tag Version: 'CIS_MongoDB_3.6_Benchmark_v1.0.0'
    describe service("mongod.service") do
      it { should be_installed }
      it { should be_running }
      it { should be_enabled }
    end
  end

control "mongod-Operating-System-Hardening-2" do
    title "Ensure that MongoDB uses a non-default port"
    desc "Changing the default port used by MongoDB makes it harder for attackers to find the
          database and target it."
    impact 1.0
    tag Vulnerability: 'Medium'
    tag Version: 'CIS_MongoDB_3.6_Benchmark_v1.0.0'
    tag Remedy:"Change the port for MongoDB server to a number other than 27017 ."
    ref 'Default mongodb Port', url: 'https://docs.mongodb.com/v3.6/reference/default-mongodb-port/'
    describe conf_file do
    its(["net", "port"]) { should_not eq 27017 }
    end
end


