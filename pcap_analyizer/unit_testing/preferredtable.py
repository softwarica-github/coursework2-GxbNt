import unittest
from unittest.mock import patch, MagicMock
from main import preferred_table, messagebox, CTkToplevel, Table

class TestPreferredTable(unittest.TestCase):

    @patch('main.choosed_cols')
    @patch('main.CTkToplevel')
    @patch('main.messagebox.showerror')
    def test_preferred_table_no_cols(self, mock_showerror, mock_CTkToplevel, mock_choosed_cols):
        # Set up mock for choosed_cols.get()
        mock_choosed_cols.get.return_value = ""

        # Call the function
        preferred_table()

        # Assertions
        mock_showerror.assert_called_once_with("Error", "Try entering the columns name separated by space")
        mock_CTkToplevel.assert_not_called()

    @patch('main.choosed_cols')
    @patch('main.Table')
    @patch('main.CTkToplevel')
    def test_preferred_table_with_cols(self, mock_CTkToplevel, mock_Table, mock_choosed_cols):
        # Set up mock for choosed_cols.get()
        mock_choosed_cols.get.return_value = "col1 col2 col3"

        # Call the function
        preferred_table()

        # Assertions
        mock_Table.assert_called_once_with(mock_CTkToplevel.return_value, dataframe=unittest.mock.ANY, showtoolbar=True, showstatusbar=True, width=1500, height=800)
        mock_Table.return_value.show.assert_called_once()

    @patch('main.choosed_cols')
    @patch('main.messagebox.showerror')
    def test_preferred_table_exception(self, mock_showerror, mock_choosed_cols):
        # Set up mock for choosed_cols.get() to raise an exception
        mock_choosed_cols.get.side_effect = Exception

        # Call the function
        preferred_table()

        # Assertions
        mock_showerror.assert_called_once_with("Error", "Only No Column with that name Exists! Try seeing the column names")

if __name__ == '__main__':
    unittest.main()
