import os
import tempfile

from vulnscout.scanner.code_fetcher import CodeFetcher, CodeFetchError


def test_fetch_local_valid_directory():
    with tempfile.TemporaryDirectory() as tmpdir:
        fetcher = CodeFetcher()
        result = fetcher.fetch_local(tmpdir)
        assert result.exists()
        assert result.is_dir()


def test_fetch_local_nonexistent():
    fetcher = CodeFetcher()
    try:
        fetcher.fetch_local("/nonexistent/path")
        assert False, "Should have raised"
    except CodeFetchError:
        pass


def test_fetch_local_file():
    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(b"test")
        f.flush()
        try:
            fetcher = CodeFetcher()
            fetcher.fetch_local(f.name)
            assert False, "Should have raised"
        except CodeFetchError:
            pass
        finally:
            os.unlink(f.name)
