// SPDX-License-Identifier: Apache-2.0

import XCTest

final class PreprodAccessTests: XCTestCase {
    @MainActor
    func testMissingProjectIdOpensNativeSecureInput() {
        continueAfterFailure = false
        let app = XCUIApplication(bundleIdentifier: "io.medianox.oxid")
        app.launch()

        let configure = app.buttons["Enter project ID"]
        XCTAssertTrue(configure.waitForExistence(timeout: 20))
        let missing = app.descendants(matching: .any).matching(
            NSPredicate(
                format: "label CONTAINS %@",
                "PreProd network access needs a Blockfrost project ID"
            )
        ).firstMatch
        XCTAssertTrue(missing.exists, app.debugDescription)
        configure.tap()

        let secureField = app.secureTextFields["preprod-project-id"]
        XCTAssertTrue(secureField.waitForExistence(timeout: 10))
        app.alerts.buttons["Cancel"].tap()

        let retry = app.buttons["Retry connection"]
        XCTAssertTrue(retry.waitForExistence(timeout: 10))
        retry.tap()
        XCTAssertTrue(configure.waitForExistence(timeout: 20))
        XCTAssertFalse(app.buttons["Create private wallet"].exists)
    }
}
