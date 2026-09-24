import Foundation

public struct TestError: Error, CustomStringConvertible {
    public let message: String
    public init(_ message: String) { self.message = message }
    public var description: String { message }
}

@MainActor
public struct TestSuite {
    public static var totalTests = 0
    public static var passedTests = 0
    public static var failedTests = 0

    public static func run(_ name: String, test: () async throws -> Void) async {
        totalTests += 1
        print("  ⏳ [RUN] \(name)...", terminator: " ")
        fflush(stdout)
        do {
            try await test()
            passedTests += 1
            print("\u{001B}[32m[PASS]\u{001B}[0m")
        } catch {
            failedTests += 1
            print("\u{001B}[31m[FAIL]\u{001B}[0m\n     ❌ \(error)")
        }
    }

    public static func assertEqual<T: Equatable>(_ a: T, _ b: T, _ message: String = "", file: StaticString = #file, line: UInt = #line) throws {
        if a != b {
            throw TestError("Expected \(a) to equal \(b). \(message) (\(file):\(line))")
        }
    }

    public static func assertTrue(_ condition: Bool, _ message: String = "", file: StaticString = #file, line: UInt = #line) throws {
        if !condition {
            throw TestError("Expected condition to be true. \(message) (\(file):\(line))")
        }
    }

    public static func assertFalse(_ condition: Bool, _ message: String = "", file: StaticString = #file, line: UInt = #line) throws {
        if condition {
            throw TestError("Expected condition to be false. \(message) (\(file):\(line))")
        }
    }

    public static func printSummary() -> Int32 {
        print("\n=======================================================")
        if failedTests == 0 {
            print("\u{001B}[32m✅ ALL \(passedTests) TESTS PASSED SUCCESSFULLY!\u{001B}[0m")
        } else {
            print("\u{001B}[31m❌ \(failedTests) OF \(totalTests) TESTS FAILED!\u{001B}[0m")
        }
        print("=======================================================\n")
        return failedTests == 0 ? 0 : 1
    }
}
