package com.stratio.marathonlbsec.functionalAT;

import com.stratio.qa.cucumber.testng.CucumberRunner;
import com.stratio.tests.utils.BaseTest;
import cucumber.api.CucumberOptions;
import org.testng.annotations.Test;
import org.testng.annotations.Factory;
import com.stratio.qa.data.BrowsersDataProvider;

@CucumberOptions(features = { "src/test/resources/features/functionalAT/purge.feature" })
public class Purge_IT extends BaseTest {

    public Purge_IT() {
    }

    @Test(enabled = true, groups = {"purge"})
    public void purge() throws Exception {
        new CucumberRunner(this.getClass()).runCukes();
    }
}
