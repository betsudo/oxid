// SPDX-License-Identifier: Apache-2.0

import XCTest

final class PreviewAccessTests: XCTestCase {
    // The signed Preview fixture uses a reserved node hostname.
    @MainActor
    func testUnavailableNodeKeepsStartupOpenForRetry() {
        continueAfterFailure = false
        let app = XCUIApplication(bundleIdentifier: "io.medianox.oxid")
        app.launch()

        let retry = app.buttons["Retry connection"]
        let unavailable = app.staticTexts.matching(NSPredicate(
            format: "label CONTAINS %@",
            "authenticated Midnight chain identity is unavailable"
        )).firstMatch
        XCTAssertTrue(retry.waitForExistence(timeout: 30))
        XCTAssertTrue(unavailable.exists)
        XCTAssertFalse(app.buttons["Enter project ID"].exists)
        XCTAssertFalse(app.buttons["Create private wallet"].exists)

        retry.tap()
        XCTAssertTrue(retry.waitForExistence(timeout: 30))
        XCTAssertTrue(unavailable.exists)
        XCTAssertFalse(app.buttons["Create private wallet"].exists)
    }
}
