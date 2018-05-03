package com.stratio.marathonlbsec.functionalAT;

import com.stratio.qa.cucumber.testng.CucumberRunner;
import com.stratio.tests.utils.BaseTest;
import cucumber.api.CucumberOptions;
import org.testng.annotations.Test;

@CucumberOptions(features = {
        "src/test/resources/features/functionalAT/MARATHONLB_1388/MARATHONLB_1388_CentralizedLogs.feature",

})

public class QATM_1388_Logs_IT extends BaseTest {

    public QATM_1388_Logs_IT() {
    }

    @Test(enabled = true, groups = {"logs"})
    public void QATM1388_Logs() throws Exception {
        new CucumberRunner(this.getClass()).runCukes();
    }
}
