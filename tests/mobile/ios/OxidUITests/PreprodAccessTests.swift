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

    // Use the signed keychain fixture. Its deliberately unapproved node
    // route is rejected after Keychain lookup and before any network request.
    @MainActor
    func testProjectIdPersistsAcrossRelaunch() {
        continueAfterFailure = false
        let app = XCUIApplication(bundleIdentifier: "io.medianox.oxid")
        app.launch()
        let configure = app.buttons["Enter project ID"]
        XCTAssertTrue(configure.waitForExistence(timeout: 20))
        let missing = app.staticTexts.matching(NSPredicate(
            format: "label CONTAINS %@", "needs a Blockfrost project ID"
        )).firstMatch
        XCTAssertTrue(missing.waitForExistence(timeout: 10))
        configure.tap()

        let input = app.secureTextFields["preprod-project-id"]
        XCTAssertTrue(input.waitForExistence(timeout: 10))
        input.tap()
        input.typeText("nightpreprod" + String(repeating: "Z", count: 32))
        app.alerts.buttons["Save"].tap()

        let retry = app.buttons["Retry connection"]
        XCTAssertTrue(retry.waitForExistence(timeout: 10))
        retry.tap()
        let guarded = app.staticTexts.matching(NSPredicate(
            format: "label CONTAINS %@", "authenticated Midnight deployment profile is invalid"
        )).firstMatch
        XCTAssertTrue(guarded.waitForExistence(timeout: 15), app.debugDescription)
        XCTAssertFalse(app.buttons["Create private wallet"].exists)

        app.terminate()
        app.launch()
        XCTAssertTrue(guarded.waitForExistence(timeout: 15), app.debugDescription)
        XCTAssertFalse(missing.exists)
        XCTAssertFalse(configure.exists)
        XCTAssertFalse(app.buttons["Create private wallet"].exists)
    }
}
