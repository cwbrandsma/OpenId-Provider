using System;
using System.Reflection;

namespace UnityMG.OpenId.Provider.Code
{
    public class MigrationRunner
    {
        public static void Execute(string providerName, string connectionString)
        {
            try
            {
                var assembly = Assembly.GetExecutingAssembly();
                var migrator = new global::Migrator.Migrator(providerName, connectionString, assembly);
                migrator.MigrateToLastVersion();
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
            }
        }
    }
}