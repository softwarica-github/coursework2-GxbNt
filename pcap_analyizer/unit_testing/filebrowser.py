import unittest
from unittest.mock import patch
from tkinter import END

class TestFileBrowse(unittest.TestCase):
    
    @patch('main.filedialog.askopenfilename', return_value='test.pcap')
    def test_filebrowse(self, mock_askopenfilename):
        # Importing here to ensure that the main module is loaded after patching
        import main
        
        # Create a mock CTkEntry
        class MockEntry:
            def __init__(self):
                self.text = ''
            def delete(self, start, end=None):
                self.text = ''
            def insert(self, index, text):
                self.text = text
        
        # Create a mock CTkButton
        class MockButton:
            def __init__(self):
                pass
            def grid(self, row, column):
                pass
        
        # Create mock objects
        main.file_entry = MockEntry()
        main.analyze_progres = None  # No need to mock progress bar for this test
        main.file_search_button = MockButton()
        
        # Call the function to be tested
        main.filebrowse()
        
        # Check if filedialog.askopenfilename() was called
        mock_askopenfilename.assert_called_once_with(title="Select a file", filetypes=(("pcap files", "*.pcap"), ("all files", "*.*")))
        
        # Check if file_entry was updated correctly
        self.assertEqual(main.file_entry.text, 'test.pcap')
        
if __name__ == '__main__':
    unittest.main()
