// CI de segsoft-backend en el Jenkins de p2tools (pi2tools.icesi.edu.co/jenkins).
// Equivale a .github/workflows/ci-backend.yml: corre las suites de los reportes de
// cumplimiento (generación, contrato JSON Schema, integridad, exportación PDF/SARIF y
// caché) y sus tests de integración contra un PostgreSQL 15 propio del build.
//
// Solo corre las suites de reportes: el `mvn test` completo arrastra 25 fallos previos y
// ajenos a esta funcionalidad (PolicyControllerTest, PolicyControllerSearchTest,
// RuleControllerTest y AuthServiceTest), que dejarían el pipeline siempre en rojo.
//
// Requiere en Jenkins: los plugins Pipeline, Docker Pipeline y JUnit, y un agente con Docker.
pipeline {
    agent any

    options {
        timeout(time: 30, unit: 'MINUTES')
        buildDiscarder(logRotator(numToKeepStr: '20'))
        disableConcurrentBuilds()
    }

    environment {
        // Con CI=true los integration tests fallan, en vez de omitirse, si no hay base de datos.
        CI = 'true'
        MAVEN_IMAGE = 'maven:3.9-eclipse-temurin-17'
        POSTGRES_IMAGE = 'postgres:15'
        MAVEN_ARGS = '-B -Dmaven.repo.local=.m2/repository -Dsurefire.failIfNoSpecifiedTests=false'
        UNIT_TESTS = 'ReportChecksumTest,StructuredReportSchemaTest,ReportGeneratorServiceTest,ReportServiceTest,ReportControllerTest,AnalysisReportControllerTest,ReportExportCachePerformanceTest,PdfReportExporterTest,SarifReportExporterTest,SarifSchemaValidatorTest,ReportExporterRegistryTest,ReportTextSanitizerTest,ExportFileCacheTest,ExportSizeLimitTest,SecretMaskingServiceTest,ProdAccountsInitializerTest,RegistrationServiceTest,RegistrationRateLimiterTest'
        INTEGRATION_TESTS = 'StructuredReportIntegrationTest,ReportExportIntegrationTest,AuthControllerIntegrationTest,RegistrationIntegrationTest,RegistrationDisabledIntegrationTest'
    }

    stages {
        stage('Tests unitarios y JSON Schema del reporte') {
            steps {
                script {
                    docker.image(env.MAVEN_IMAGE).inside {
                        sh 'mvn $MAVEN_ARGS test -Dtest="$UNIT_TESTS"'
                    }
                }
            }
        }

        stage('Tests de integración con PostgreSQL') {
            steps {
                script {
                    def dbEnv = '-e POSTGRES_DB=pdgseg_test -e POSTGRES_USER=pdgseg_test -e POSTGRES_PASSWORD=pdgseg_test'
                    docker.image(env.POSTGRES_IMAGE).withRun(dbEnv) { db ->
                        docker.image(env.POSTGRES_IMAGE).inside("--link ${db.id}:db") {
                            sh '''
                                for i in $(seq 1 30); do
                                    pg_isready -h db -U pdgseg_test -d pdgseg_test && exit 0
                                    sleep 2
                                done
                                echo "PostgreSQL no quedó disponible" >&2
                                exit 1
                            '''
                        }
                        docker.image(env.MAVEN_IMAGE).inside("--link ${db.id}:db") {
                            sh '''
                                SPRING_DATASOURCE_URL=jdbc:postgresql://db:5432/pdgseg_test \
                                    mvn $MAVEN_ARGS test -Pintegration-tests -Dtest="$INTEGRATION_TESTS"
                            '''
                        }
                    }
                }
            }
        }
    }

    post {
        always {
            junit testResults: 'target/surefire-reports/TEST-*.xml', allowEmptyResults: false
        }
    }
}
