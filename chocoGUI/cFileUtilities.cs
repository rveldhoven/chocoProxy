﻿using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace chocoGUI
{
    static class cFileUtilities
    {
        public static string get_sha1_hash(string Filename)
        {
            string result = "";

            using (FileStream file_stream = File.OpenRead(Filename))
            using (SHA1CryptoServiceProvider sha1 = new SHA1CryptoServiceProvider())
            {
                Stream reader = file_stream as Stream;

                result = BitConverter.ToString(sha1.ComputeHash(reader)).Replace("-", String.Empty);
            }

            return result;
        }

        public static long get_size(string Filename)
        {
            return new System.IO.FileInfo(Filename).Length;
        }

        public static string get_temp_copy(string Filename)
        {
            string temp_file = System.IO.Path.GetTempPath() + Guid.NewGuid().ToString() + ".pcap";
            
            File.Copy(Filename, temp_file);
            
            return temp_file;
        }

        public static bool remove_temp_copy(string temp_filename)
        {
            try
            {
                File.Delete(temp_filename);
            }
            catch (Exception e)
            {
                return false;
            }

            return true;
        }
    }
}
