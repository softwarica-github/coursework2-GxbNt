import unittest
from unittest.mock import MagicMock, patch
import main  # Import the main module containing the analyzer function

class TestAnalyzer(unittest.TestCase):
    @patch("main.file_entry")
    @patch("main.messagebox")
    @patch("main.rdpcap")
    @patch("main.analyze_progres")
    @patch("main.create_table_button")
    @patch("main.password_button")
    @patch("main.summarizer_button")
    @patch("main.choosed_cols_button")
    @patch("main.view_cols")
    def test_analyzer_no_file_path(self, mock_view_cols, mock_choosed_cols_button, mock_summarizer_button, 
                                   mock_password_button, mock_create_table_button, mock_analyze_progres, 
                                   mock_rdpcap, mock_messagebox, mock_file_entry):
        mock_file_entry.get.return_value = ""  # Simulate no file path provided
        main.analyzer()
        mock_messagebox.showerror.assert_called_once_with("Error", "Please enter a path to a pcap file")
        self.assertFalse(mock_rdpcap.called)

    # Add similar mocks for other tests...

if __name__ == "__main__":
    unittest.main()
