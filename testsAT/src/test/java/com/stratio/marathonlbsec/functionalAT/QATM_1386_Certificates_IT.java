package com.stratio.marathonlbsec.functionalAT;

import com.stratio.qa.cucumber.testng.CucumberRunner;
import com.stratio.tests.utils.BaseTest;
import cucumber.api.CucumberOptions;
import org.testng.annotations.Test;

@CucumberOptions(features = {
        "src/test/resources/features/functionalAT/MARATHONLB_1386/01_MARATHONLB_1386_AppCertificate.feature",
        "src/test/resources/features/functionalAT/MARATHONLB_1386/02_MARATHONLB_1386_ClientCertificate.feature"
})

public class QATM_1386_Certificates_IT extends BaseTest {

    public QATM_1386_Certificates_IT() {
    }

    @Test(enabled = true, groups = {"certificates"})
    public void QATM1386_Certificates() throws Exception {
        new CucumberRunner(this.getClass()).runCukes();
    }
}
