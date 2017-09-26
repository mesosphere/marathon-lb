@Library('libpipelines@master') _

hose {
    EMAIL = 'qa'
    DEVTIMEOUT = 20
    RELEASETIMEOUT = 20
    PKGMODULESNAMES = ['marathon-lb-sec']
    BUILDTOOL = 'make'
    INSTALLTIMEOUT = 20

    INSTALLSERVICES = [
            ['DCOSCLI':   ['image': 'stratio/dcos-cli:0.4.15',
			   'volumes': ['stratio/paasintegrationpem:0.1.0'],
                           'env':     ['DCOS_IP=10.200.0.205',
                                      'SSL=true',
				      'SSH=true',
                                      'TOKEN_AUTHENTICATION=true',
                                      'DCOS_USER=admin@demo.stratio.com',
                                      'DCOS_PASSWORD=1234',
                                      'BOOTSTRAP_USER=operador',
                                      'PEM_FILE_PATH=/paascerts/PaasIntegration.pem'],
                           'sleep':  10]]
        ]

    INSTALLPARAMETERS = """
                    | -DDCOS_CLI_HOST=%%DCOSCLI#0
                    | -DDCOS_CLI_USER=root
                    | -DDCOS_CLI_PASSWORD=stratio
                    | -DDCOS_IP=10.200.0.205
                    | -DDCOS_USER=admin@demo.stratio.com
                    | -DREMOTE_USER=root
                    | -DREMOTE_PASSWORD=stratio
                    | -DPEM_FILE=none
                    | -DVAULT_HOST=gosec2.node.paas.labs.stratio.com
                    | -DVAULT_PORT=8200
                    | """.stripMargin().stripIndent()

    DEV = { config ->
        doDocker(config)
    }

    INSTALL = { config ->
        doAT(conf: config, groups: ['marathonlbdefault'])
    }
}
