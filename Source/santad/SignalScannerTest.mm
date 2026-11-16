/// Copyright 2026 North Pole Security, Inc.
///
/// Licensed under the Apache License, Version 2.0 (the "License");
/// you may not use this file except in compliance with the License.
/// You may obtain a copy of the License at
///
///     http://www.apache.org/licenses/LICENSE-2.0
///
/// Unless required by applicable law or agreed to in writing, software
/// distributed under the License is distributed on an "AS IS" BASIS,
/// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
/// See the License for the specific language governing permissions and
/// limitations under the License.

#import <XCTest/XCTest.h>

#include <fcntl.h>

#include <functional>
#include <limits>

#include "Source/santad/SignalScanner.h"

namespace santa {
class SignalScannerPeer {
 public:
  static std::shared_ptr<SignalScanner> Create(std::unique_ptr<SleighLauncher> launcher,
                                               dispatch_queue_t queue, uint32_t timeout = 10,
                                               SignalScanner::ReportHandlerBlock handler = nil) {
    return std::shared_ptr<SignalScanner>(
        new SignalScanner(std::move(launcher), timeout, handler, queue));
  }
};
}  // namespace santa

namespace {
class RecordingLauncher : public santa::SleighLauncher {
 public:
  RecordingLauncher() : SleighLauncher("unused") {}

  absl::StatusOr<::santa::telemetry::v1::SleighSignalScanResponse> LaunchSignalScan(
      const std::vector<int>& fds, const std::vector<std::string>& signals,
      uint32_t timeout) override {
    std::vector<char> contents;
    for (int fd : fds) {
      char c = 0;
      if (read(fd, &c, 1) != 1) return absl::InternalError("Unreadable input");
      contents.push_back(c);
    }
    batches.push_back(contents);
    timeouts.push_back(timeout);
    received_signals.push_back(signals);
    if (on_scan) on_scan();
    if (fail) return absl::InternalError("Scan failed");
    ::santa::telemetry::v1::SleighSignalScanResponse response;
    response.add_signal_reports()->set_name("test");
    return response;
  }

  std::vector<std::vector<char>> batches;
  std::vector<uint32_t> timeouts;
  std::vector<std::vector<std::string>> received_signals;
  std::function<void()> on_scan;
  bool fail = false;
};

std::shared_ptr<santa::ScopedFile> Input(char contents) {
  auto file = santa::ScopedFile::CreateTemporary();
  if (!file.ok()) return nullptr;
  if (write(file->UnsafeFD(), &contents, 1) != 1 || lseek(file->UnsafeFD(), 0, SEEK_SET) != 0) {
    return nullptr;
  }
  return std::make_shared<santa::ScopedFile>(std::move(*file));
}

void SetSignal(const std::shared_ptr<santa::SignalScanner>& scanner, NSString* value = @"signal") {
  scanner->SetSignals(
      @[ [[SNTSignal alloc] initAddRuleWithName:@"test"
                                           data:[value dataUsingEncoding:NSUTF8StringEncoding]] ]);
}
}  // namespace

@interface SignalScannerTest : XCTestCase
@end

@implementation SignalScannerTest

- (void)testBatchesQueuedFilesInOrderAndReleasesUnlinkedInputs {
  dispatch_queue_t queue = dispatch_queue_create("signal-test", DISPATCH_QUEUE_SERIAL);
  dispatch_suspend(queue);
  auto launcher = std::make_unique<RecordingLauncher>();
  auto* recorded = launcher.get();
  __block NSUInteger reports = 0;
  auto scanner = santa::SignalScannerPeer::Create(
      std::move(launcher), queue, 10, ^(NSArray<SNTStoredSignalReport*>* batch) {
        reports += batch.count;
        XCTAssertEqualObjects(batch.firstObject.name, @"test");
      });
  SetSignal(scanner);
  std::vector<int> fds;
  for (char i = 0; i < 17; ++i) {
    auto file = Input(i);
    XCTAssertNotEqual(file, nullptr);
    fds.push_back(file->UnsafeFD());
    scanner->ScanFile(std::to_string(i), std::move(file));
  }
  dispatch_resume(queue);
  dispatch_sync(queue, ^{
                });
  XCTAssertEqual(recorded->batches.size(), 3u);
  XCTAssertEqual(recorded->batches[0].size(), 8u);
  XCTAssertEqual(recorded->batches[1].size(), 8u);
  XCTAssertEqual(recorded->batches[2].size(), 1u);
  char expected = 0;
  for (const auto& batch : recorded->batches) {
    for (char c : batch)
      XCTAssertEqual(c, expected++);
  }
  XCTAssertEqual(recorded->timeouts, (std::vector<uint32_t>{80, 80, 10}));
  XCTAssertEqual(reports, 3u);
  for (int fd : fds)
    XCTAssertEqual(fcntl(fd, F_GETFD), -1);
}

- (void)testSingleFileStartsWithoutWaitingForAnotherFile {
  dispatch_queue_t queue = dispatch_queue_create("signal-test", DISPATCH_QUEUE_SERIAL);
  auto launcher = std::make_unique<RecordingLauncher>();
  auto* recorded = launcher.get();
  auto scanner = santa::SignalScannerPeer::Create(std::move(launcher), queue);
  SetSignal(scanner);
  scanner->ScanFile("first", Input('a'));
  dispatch_sync(queue, ^{
                });
  scanner->ScanFile("second", Input('b'));
  dispatch_sync(queue, ^{
                });
  XCTAssertEqual(recorded->batches, (std::vector<std::vector<char>>{{'a'}, {'b'}}));
}

- (void)testArrivalDuringScanIsScheduled {
  dispatch_queue_t queue = dispatch_queue_create("signal-test", DISPATCH_QUEUE_SERIAL);
  auto launcher = std::make_unique<RecordingLauncher>();
  auto* recorded = launcher.get();
  auto scanner = santa::SignalScannerPeer::Create(std::move(launcher), queue);
  SetSignal(scanner);
  recorded->on_scan = [&] {
    if (recorded->batches.size() == 1) scanner->ScanFile("later", Input('b'));
  };
  scanner->ScanFile("first", Input('a'));
  dispatch_sync(queue, ^{
                });
  dispatch_sync(queue, ^{
                });
  XCTAssertEqual(recorded->batches, (std::vector<std::vector<char>>{{'a'}, {'b'}}));
}

- (void)testNoSignalsSkipsLaunchAndReleasesInput {
  dispatch_queue_t queue = dispatch_queue_create("signal-test", DISPATCH_QUEUE_SERIAL);
  auto launcher = std::make_unique<RecordingLauncher>();
  auto* recorded = launcher.get();
  auto scanner = santa::SignalScannerPeer::Create(std::move(launcher), queue);
  auto input = Input('a');
  int fd = input->UnsafeFD();
  scanner->ScanFile("no-signals", std::move(input));
  scanner->ScanFile("no-file", nullptr);
  dispatch_sync(queue, ^{
                });
  XCTAssertTrue(recorded->batches.empty());
  XCTAssertEqual(fcntl(fd, F_GETFD), -1);
}

- (void)testPendingBatchUsesLatestSignals {
  dispatch_queue_t queue = dispatch_queue_create("signal-test", DISPATCH_QUEUE_SERIAL);
  dispatch_suspend(queue);
  auto launcher = std::make_unique<RecordingLauncher>();
  auto* recorded = launcher.get();
  auto scanner = santa::SignalScannerPeer::Create(std::move(launcher), queue);
  SetSignal(scanner, @"old");
  scanner->ScanFile("pending", Input('a'));
  SetSignal(scanner, @"new");
  dispatch_resume(queue);
  dispatch_sync(queue, ^{
                });
  XCTAssertEqual(recorded->received_signals[0], (std::vector<std::string>{"new"}));
}

- (void)testFailureReleasesDescriptorsAndCapacity {
  dispatch_queue_t queue = dispatch_queue_create("signal-test", DISPATCH_QUEUE_SERIAL);
  dispatch_suspend(queue);
  auto launcher = std::make_unique<RecordingLauncher>();
  auto* recorded = launcher.get();
  recorded->fail = true;
  auto scanner = santa::SignalScannerPeer::Create(std::move(launcher), queue);
  SetSignal(scanner);
  std::vector<int> fds;
  for (int i = 0; i < 101; ++i) {
    auto input = Input('a');
    fds.push_back(input->UnsafeFD());
    scanner->ScanFile("pending", std::move(input));
  }
  dispatch_resume(queue);
  dispatch_sync(queue, ^{
                });
  size_t count = 0;
  for (const auto& batch : recorded->batches)
    count += batch.size();
  XCTAssertEqual(count, 100u);
  XCTAssertEqual(recorded->batches.size(), 13u);
  for (int fd : fds)
    XCTAssertEqual(fcntl(fd, F_GETFD), -1);
  recorded->fail = false;
  scanner->ScanFile("after-failure", Input('b'));
  dispatch_sync(queue, ^{
                });
  XCTAssertEqual(recorded->batches.back(), (std::vector<char>{'b'}));
}

- (void)testTimeoutSaturates {
  dispatch_queue_t queue = dispatch_queue_create("signal-test", DISPATCH_QUEUE_SERIAL);
  dispatch_suspend(queue);
  auto launcher = std::make_unique<RecordingLauncher>();
  auto* recorded = launcher.get();
  auto scanner = santa::SignalScannerPeer::Create(std::move(launcher), queue,
                                                  std::numeric_limits<uint32_t>::max());
  SetSignal(scanner);
  scanner->ScanFile("a", Input('a'));
  scanner->ScanFile("b", Input('b'));
  dispatch_resume(queue);
  dispatch_sync(queue, ^{
                });
  XCTAssertEqual(recorded->timeouts[0], std::numeric_limits<uint32_t>::max());
}
@end
