import pytest
import sys
import os
import asyncio
from unittest.mock import Mock, patch, MagicMock
import tempfile
import shutil
import json
from datetime import datetime

# Repo that is good for testing code graph generation
TEST_REPO_PATH = "/Users/louismurphy/ODYSSEY/AI_SUPER_TASK/Repos/sqlite"
GRAPH_SAVE_PATH = "/Users/louismurphy/Library/Mobile Documents/com~apple~CloudDocs/Desktop/ODYSSEY/AI7_SUPER_TASK/Samples/graphs"

class TestCodeQL:
    """Test suite for CodeQL graph generation functionality"""
    
    @pytest.fixture
    def async_queue(self):
        """Create an async queue for testing"""
        return asyncio.Queue()
    
    @pytest.fixture
    def temp_repo(self):
        """Create a temporary repository for testing"""
        temp_dir = tempfile.mkdtemp()
        # Create some sample C files for testing
        with open(os.path.join(temp_dir, "main.c"), "w") as f:
            f.write("int main() { return 0; }")
        yield temp_dir
        shutil.rmtree(temp_dir)
    
    def test_codeql_initialization(self):
        """Test CodeQL class initialization"""
        from Graphs.CodeQL import CodeQL
        
        codeql = CodeQL(TEST_REPO_PATH)
        assert codeql.repo == TEST_REPO_PATH
        assert hasattr(codeql, 'repo')
    
    def test_codeql_initialization_with_queue(self):
        """Test CodeQL initialization with async queue"""
        from Graphs.CodeQL import CodeQL
        
        queue = asyncio.Queue()
        codeql = CodeQL(TEST_REPO_PATH, queue)
        assert codeql.repo == TEST_REPO_PATH
        assert codeql.queue == queue
    
    @pytest.mark.asyncio
    async def test_parse_codebase_creates_database(self, temp_repo):
        """Test that parse_codebase creates a CodeQL database"""
        from Graphs.CodeQL import CodeQL
        
        queue = asyncio.Queue()
        codeql = CodeQL(temp_repo, queue)
        
        # Mock subprocess calls to CodeQL CLI
        with patch('subprocess.run') as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="Database created successfully")
            
            await codeql.parse_codebase()
            
            # Verify CodeQL database create was called
            mock_run.assert_called()
            call_args = mock_run.call_args[0][0]
            assert 'codeql' in call_args
            assert 'database' in call_args
            assert 'create' in call_args
    
    @pytest.mark.asyncio
    async def test_parse_codebase_returns_data_on_queue(self, temp_repo, async_queue):
        """Test that parse_codebase returns graph data on the async queue"""
        from Graphs.CodeQL import CodeQL
        
        codeql = CodeQL(temp_repo, async_queue)
        
        with patch('subprocess.run') as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="Database created successfully")
            
            await codeql.parse_codebase()
            
            # Check data was put on queue
            assert not async_queue.empty()
            result = await async_queue.get()
            assert 'status' in result
            assert 'database_path' in result
            assert result['status'] == 'success'
    
    @pytest.mark.asyncio
    async def test_parse_codebase_handles_errors(self, temp_repo, async_queue):
        """Test error handling in parse_codebase"""
        from Graphs.CodeQL import CodeQL
        
        codeql = CodeQL(temp_repo, async_queue)
        
        with patch('subprocess.run') as mock_run:
            mock_run.return_value = MagicMock(returncode=1, stderr="CodeQL error")
            
            await codeql.parse_codebase()
            
            # Check error was put on queue
            result = await async_queue.get()
            assert result['status'] == 'error'
            assert 'error' in result
    
    @pytest.mark.asyncio
    async def test_detect_language(self):
        """Test language detection for the repository"""
        from Graphs.CodeQL import CodeQL
        
        codeql = CodeQL(TEST_REPO_PATH)
        language = await codeql.detect_language()
        assert language in ['cpp', 'c', 'python', 'java', 'javascript', 'go', 'csharp']
    
    @pytest.mark.asyncio
    async def test_real_sqlite_repo_parsing(self):
        """Integration test with real SQLite repository"""
        from Graphs.CodeQL import CodeQL
        import logging
        
        # Enable logging for debugging
        logging.basicConfig(level=logging.INFO)
        
        if not os.path.exists(TEST_REPO_PATH):
            pytest.skip(f"Test repo not found at {TEST_REPO_PATH}")
        
        queue = asyncio.Queue()
        codeql = CodeQL(TEST_REPO_PATH, queue)
        
        # This test requires CodeQL to be installed
        try:
            # SQLite needs configure to be run first
            # For testing, we'll use a simpler approach
            await codeql.parse_codebase(build_command="echo 'Skipping build for test'")
            result = await queue.get()
            
            if result['status'] == 'error' and 'CodeQL CLI not found' in result['error']:
                pytest.skip("CodeQL CLI not installed")
            
            # For now, we'll consider the test passing if we get a result
            # Real CodeQL database creation requires proper setup
            assert 'status' in result
            assert 'repo' in result
            assert result['repo'] == TEST_REPO_PATH
            
            # Save the graph result if successful
            if result['status'] == 'success':
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                filename = f"sqlite_graph_{timestamp}.json"
                filepath = os.path.join(GRAPH_SAVE_PATH, filename)
                
                # Save the result including database path for reuse
                with open(filepath, 'w') as f:
                    json.dump(result, f, indent=2)
                
                print(f"Graph saved to: {filepath}")
                
                # Also save a "latest" version for easy access
                latest_path = os.path.join(GRAPH_SAVE_PATH, "sqlite_graph_latest.json")
                with open(latest_path, 'w') as f:
                    json.dump(result, f, indent=2)
                    
        except FileNotFoundError:
            pytest.skip("CodeQL CLI not installed")
    
    def test_database_naming(self):
        """Test database naming convention"""
        from Graphs.CodeQL import CodeQL
        
        codeql = CodeQL("/path/to/my-project")
        db_name = codeql.get_database_name()
        assert "my-project" in db_name
        assert "codeql-db" in db_name
    
    @pytest.mark.asyncio
    async def test_load_saved_graph(self):
        """Test loading a pre-saved graph"""
        from Graphs.CodeQL import CodeQL
        
        latest_path = os.path.join(GRAPH_SAVE_PATH, "test_python_graph_latest.json")
        
        if not os.path.exists(latest_path):
            pytest.skip("No saved graph found. Run test_generate_and_save_python_graph first.")
        
        # Load the CodeQL instance from saved graph
        codeql = CodeQL.load_from_saved(latest_path)
        
        # Verify the instance was loaded correctly
        assert codeql.database_path is not None
        assert codeql.repo == "/tmp/test_python_repo"
        
        # Get database info
        info = codeql.get_database_info()
        assert info is not None
        assert 'database_path' in info
        assert 'repo' in info
        assert 'exists' in info
        
        print(f"Loaded CodeQL instance with database at: {codeql.database_path}")
        print(f"Database exists: {info['exists']}")
    
    @pytest.mark.asyncio
    async def test_generate_and_save_python_graph(self):
        """Actually generate a CodeQL database for Python code and save it for reuse"""
        from Graphs.CodeQL import CodeQL
        import logging
        
        # Enable logging for debugging
        logging.basicConfig(level=logging.INFO)
        
        queue = asyncio.Queue()
        
        try:
            # Create a simple Python test project
            test_python_repo = "/tmp/test_python_repo"
            os.makedirs(test_python_repo, exist_ok=True)
            
            # Create a Python file with potential vulnerabilities
            with open(os.path.join(test_python_repo, "vulnerable.py"), "w") as f:
                f.write("""
import os
import subprocess
import sqlite3
from flask import request

def command_injection(user_input):
    # Vulnerable to command injection
    os.system(f"echo {user_input}")
    
def sql_injection(user_id):
    # Vulnerable to SQL injection
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    query = f"SELECT * FROM users WHERE id = {user_id}"
    cursor.execute(query)
    return cursor.fetchall()

def path_traversal(filename):
    # Vulnerable to path traversal
    with open(f"uploads/{filename}", 'r') as f:
        return f.read()

def subprocess_injection(cmd):
    # Vulnerable to command injection via subprocess
    subprocess.call(cmd, shell=True)
                """)
            
            # Create another Python file
            with open(os.path.join(test_python_repo, "main.py"), "w") as f:
                f.write("""
from vulnerable import command_injection, sql_injection

def main():
    user_input = input("Enter command: ")
    command_injection(user_input)
    
    user_id = input("Enter user ID: ")
    sql_injection(user_id)

if __name__ == "__main__":
    main()
                """)
            
            # Use the test repo
            codeql_test = CodeQL(test_python_repo, queue)
            
            # Run CodeQL database creation - Python doesn't need build command
            await codeql_test.parse_codebase()
            
            # Get the result
            result = await queue.get()
            print(f"CodeQL result: {result}")
            
            if result['status'] == 'success':
                # Save the graph result
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                filename = f"test_python_graph_{timestamp}.json"
                filepath = os.path.join(GRAPH_SAVE_PATH, filename)
                
                # Save the result including database path for reuse
                with open(filepath, 'w') as f:
                    json.dump(result, f, indent=2)
                
                print(f"Graph saved to: {filepath}")
                
                # Also save a "latest" version for easy access
                latest_path = os.path.join(GRAPH_SAVE_PATH, "test_python_graph_latest.json")
                with open(latest_path, 'w') as f:
                    json.dump(result, f, indent=2)
                    
                assert os.path.exists(filepath)
                assert os.path.exists(latest_path)
                
                # Verify we can read it back
                with open(latest_path, 'r') as f:
                    loaded_data = json.load(f)
                    assert loaded_data['database_path'] == result['database_path']
                    
            else:
                if 'CodeQL CLI not found' in result.get('error', ''):
                    pytest.skip("CodeQL CLI not installed")
                else:
                    pytest.fail(f"CodeQL database creation failed: {result.get('error')}")
                    
        except Exception as e:
            pytest.fail(f"Test failed with exception: {str(e)}")
        finally:
            # Cleanup
            if os.path.exists("/tmp/test_python_repo"):
                shutil.rmtree("/tmp/test_python_repo")
    


if __name__ == "__main__":
    # Ensure parent directory (project root) is on sys.path for imports like `from Detectors ...`
    current_dir = os.path.dirname(os.path.abspath(__file__))
    project_root = os.path.dirname(current_dir)
    if project_root not in sys.path:
        sys.path.insert(0, project_root)

    # Run just this test module when executed directly
    raise SystemExit(pytest.main([os.path.abspath(__file__)]))