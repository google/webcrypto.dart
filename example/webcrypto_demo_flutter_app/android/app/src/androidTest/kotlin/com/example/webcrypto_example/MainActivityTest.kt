package com.example.webcrypto_example

import androidx.test.rule.ActivityTestRule
import dev.flutter.plugins.integration_test.FlutterTestRunner
import org.junit.Rule
import org.junit.runner.RunWith

@RunWith(FlutterTestRunner::class)
class MainActivityTest {
    @Rule
    @JvmField
    val rule: ActivityTestRule<MainActivity> =
        ActivityTestRule(MainActivity::class.java, true, false)
}
