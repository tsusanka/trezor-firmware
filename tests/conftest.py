# This file is part of the Trezor project.
#
# Copyright (C) 2012-2019 SatoshiLabs and contributors
#
# This library is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License version 3
# as published by the Free Software Foundation.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the License along with this library.
# If not, see <https://www.gnu.org/licenses/lgpl-3.0.html>.

import filecmp
import itertools
import os
import re
from contextlib import contextmanager
from pathlib import Path

import pytest

from trezorlib import debuglink, log
from trezorlib.debuglink import TrezorClientDebugLink
from trezorlib.device import apply_settings, wipe as wipe_device
from trezorlib.messages.PassphraseSourceType import HOST as PASSPHRASE_ON_HOST
from trezorlib.transport import enumerate_devices, get_transport

from .device_handler import BackgroundDeviceHandler


def get_device():
    path = os.environ.get("TREZOR_PATH")
    interact = int(os.environ.get("INTERACT", 0))
    if path:
        try:
            transport = get_transport(path)
            return TrezorClientDebugLink(transport, auto_interact=not interact)
        except Exception as e:
            raise RuntimeError("Failed to open debuglink for {}".format(path)) from e

    else:
        devices = enumerate_devices()
        for device in devices:
            try:
                return TrezorClientDebugLink(device, auto_interact=not interact)
            except Exception:
                pass
        else:
            raise RuntimeError("No debuggable device found")


def _get_test_dirname(node):
    # This composes the dirname from the test module name and test item name.
    # Test item name is usually function name, but when parametrization is used,
    # parameters are also part of the name. Some functions have very long parameter
    # names (tx hashes etc) that run out of maximum allowable filename length, so
    # we limit the name to first 100 chars. This is not a problem with txhashes.
    node_name = re.sub(r"\W+", "_", node.name)[:100]
    node_module_name = node.getparent(pytest.Module).name
    return "{}_{}".format(node_module_name, node_name)


def _record_screen_fixtures(fixture_dir, test_dir):
    if fixture_dir.exists():
        # remove old fixtures
        for fixture in fixture_dir.iterdir():
            fixture.unlink()
    else:
        # create the fixture dir, if not present
        fixture_dir.mkdir()

    # move recorded screenshots into fixture directory
    records = sorted(test_dir.iterdir())
    for index, record in enumerate(sorted(records)):
        fixture = fixture_dir / "{:08}.png".format(index)
        record.replace(fixture)


def _assert_screen_recording(fixture_dir, test_dir):
    fixtures = sorted(fixture_dir.iterdir())
    records = sorted(test_dir.iterdir())

    if not fixtures:
        return

    for fixture, image in itertools.zip_longest(fixtures, records):
        if fixture is None:
            pytest.fail("Missing fixture for image {}".format(image))
        if image is None:
            pytest.fail("Missing image for fixture {}".format(fixture))
        if not filecmp.cmp(fixture, image):
            pytest.fail("Image {} and fixture {} differ".format(image, fixture))


@contextmanager
def _screen_recording(client, request, tmp_path):
    if not request.node.get_closest_marker("skip_ui"):
        test_screen = request.config.getoption("test_screen")
    else:
        test_screen = ""
    fixture_root = Path(__file__) / "../ui_tests"

    try:
        if test_screen:
            client.debug.start_recording(str(tmp_path))
        yield
    finally:
        if test_screen:
            client.debug.stop_recording()
            fixture_path = fixture_root.resolve() / _get_test_dirname(request.node)
            if test_screen == "record":
                _record_screen_fixtures(fixture_path, tmp_path)
            elif test_screen == "test":
                _assert_screen_recording(fixture_path, tmp_path)


@pytest.fixture(scope="function")
def client(request, tmp_path):
    """Client fixture.

    Every test function that requires a client instance will get it from here.
    If we can't connect to a debuggable device, the test will fail.
    If 'skip_t2' is used and TT is connected, the test is skipped. Vice versa with T1
    and 'skip_t1'.

    The client instance is wiped and preconfigured with "all all all..." mnemonic, no
    password and no pin. It is possible to customize this with the `setup_client`
    marker.

    To specify a custom mnemonic and/or custom pin and/or enable passphrase:

    @pytest.mark.setup_client(mnemonic=MY_MNEMONIC, pin="9999", passphrase=True)

    To receive a client instance that was not initialized:

    @pytest.mark.setup_client(uninitialized=True)
    """
    try:
        client = get_device()
    except RuntimeError:
        pytest.fail("No debuggable Trezor is available")

    if request.node.get_closest_marker("skip_t2") and client.features.model == "T":
        pytest.skip("Test excluded on Trezor T")
    if request.node.get_closest_marker("skip_t1") and client.features.model == "1":
        pytest.skip("Test excluded on Trezor 1")

    if (
        request.node.get_closest_marker("sd_card")
        and not client.features.sd_card_present
    ):
        raise RuntimeError(
            "This test requires SD card.\n"
            "To skip all such tests, run:\n"
            "  pytest -m 'not sd_card' <test path>"
        )

    wipe_device(client)

    # fmt: off
    setup_params = dict(
        uninitialized=False,
        mnemonic=" ".join(["all"] * 12),
        pin=None,
        passphrase=False,
        needs_backup=False,
        no_backup=False,
        random_seed=None,
    )
    # fmt: on

    marker = request.node.get_closest_marker("setup_client")
    if marker:
        setup_params.update(marker.kwargs)

    if not setup_params["uninitialized"]:
        if setup_params["pin"] is True:
            setup_params["pin"] = "1234"

        debuglink.load_device(
            client,
            mnemonic=setup_params["mnemonic"],
            pin=setup_params["pin"],
            passphrase_protection=setup_params["passphrase"],
            label="test",
            language="english",
            needs_backup=setup_params["needs_backup"],
            no_backup=setup_params["no_backup"],
        )
        if setup_params["passphrase"] and client.features.model != "1":
            apply_settings(client, passphrase_source=PASSPHRASE_ON_HOST)

        if setup_params["pin"]:
            # ClearSession locks the device. We only do that if the PIN is set.
            client.clear_session()

    client.open()

    if setup_params["random_seed"] is not None:
        client.debug.reseed(setup_params["random_seed"])

    with _screen_recording(client, request, tmp_path):
        yield client

    client.close()


def pytest_addoption(parser):
    parser.addoption(
        "--test_screen",
        action="store",
        default="",
        help="Enable UI intergration tests: 'test' or 'record'",
    )


def pytest_configure(config):
    """Called at testsuite setup time.

    Registers known markers, enables verbose output if requested.
    """
    # register known markers
    config.addinivalue_line("markers", "skip_t1: skip the test on Trezor One")
    config.addinivalue_line("markers", "skip_t2: skip the test on Trezor T")
    config.addinivalue_line(
        "markers",
        'setup_client(mnemonic="all all all...", pin=None, passphrase=False, uninitialized=False): configure the client instance',
    )
    config.addinivalue_line(
        "markers", "skip_ui: skip UI integration checks for this test"
    )
    with open(os.path.join(os.path.dirname(__file__), "REGISTERED_MARKERS")) as f:
        for line in f:
            config.addinivalue_line("markers", line.strip())

    # enable debug
    if config.getoption("verbose"):
        log.enable_debug_output()


def pytest_runtest_setup(item):
    """Called for each test item (class, individual tests).

    Ensures that altcoin tests are skipped, and that no test is skipped on
    both T1 and TT.
    """
    if item.get_closest_marker("skip_t1") and item.get_closest_marker("skip_t2"):
        raise RuntimeError("Don't skip tests for both trezors!")

    skip_altcoins = int(os.environ.get("TREZOR_PYTEST_SKIP_ALTCOINS", 0))
    if item.get_closest_marker("altcoin") and skip_altcoins:
        pytest.skip("Skipping altcoin test")


@pytest.hookimpl(tryfirst=True, hookwrapper=True)
def pytest_runtest_makereport(item, call):
    # Make test results available in fixtures.
    # See https://docs.pytest.org/en/latest/example/simple.html#making-test-result-information-available-in-fixtures
    # The device_handler fixture uses this as 'request.node.rep_call.passed' attribute,
    # in order to raise error only if the test passed.
    outcome = yield
    rep = outcome.get_result()
    setattr(item, f"rep_{rep.when}", rep)


@pytest.fixture
def device_handler(client, request):
    device_handler = BackgroundDeviceHandler(client)
    yield device_handler

    # make sure all background tasks are done
    finalized_ok = device_handler.check_finalize()
    if request.node.rep_call.passed and not finalized_ok:
        raise RuntimeError("Test did not check result of background task")
