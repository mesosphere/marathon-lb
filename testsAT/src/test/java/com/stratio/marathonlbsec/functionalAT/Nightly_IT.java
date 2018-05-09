package com.stratio.marathonlbsec.functionalAT;

import com.stratio.qa.cucumber.testng.CucumberRunner;
import com.stratio.tests.utils.BaseTest;
import cucumber.api.CucumberOptions;
import org.testng.annotations.Test;
import org.testng.annotations.Factory;
import com.stratio.qa.data.BrowsersDataProvider;

@CucumberOptions(features = {
        "src/test/resources/features/functionalAT/010_installation.feature",
        "src/test/resources/features/functionalAT/MARATHONLB_1386/01_MARATHONLB_1386_AppCertificate.feature",
        "src/test/resources/features/functionalAT/MARATHONLB_1386/02_MARATHONLB_1386_ClientCertificate.feature",
        "src/test/resources/features/functionalAT/MARATHONLB_1388/MARATHONLB_1388_CentralizedLogs.feature"
        //"src/test/resources/features/functionalAT/purge.feature"

})
public class Nightly_IT extends BaseTest {

    public Nightly_IT() {
    }

    @Test(enabled = true, groups = {"nightly"})
    public void nightly() throws Exception {
        new CucumberRunner(this.getClass()).runCukes();
    }
}
