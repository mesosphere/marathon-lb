package com.stratio.marathonlbsec.functionalAT;

import com.stratio.qa.cucumber.testng.CucumberRunner;
import com.stratio.tests.utils.BaseTest;
import cucumber.api.CucumberOptions;
import org.testng.annotations.Test;
import org.testng.annotations.Factory;
import com.stratio.qa.data.BrowsersDataProvider;

@CucumberOptions(features = { "src/test/resources/features/functionalAT/010_installation.feature" })
public class Installation_IT extends BaseTest {

    public Installation_IT() {
    }

    @Test(enabled = true, groups = {"installation"})
    public void installation() throws Exception {
        new CucumberRunner(this.getClass()).runCukes();
    }
}
