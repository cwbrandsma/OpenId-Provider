using System.Data;
using System.Data.Entity;
using Migrator.Framework;

namespace DapperMembershipProvider.Migrations
{
    [Migration(20120521162201)]
    public class MigrationMembershipUser_001 : Migration
    {
        public override void Up()
        {
            Database.AddTable("Membership_User",
                new Column("UserId", DbType.Guid, ColumnProperty.PrimaryKey),
                new Column("UserName", DbType.String, 256),
                new Column("Password", DbType.String, 128),
                new Column("Salt", DbType.String, 128),
                new Column("Email", DbType.String, 256),
                new Column("PasswordQuestion", DbType.String, 256),
                new Column("PasswordAnswer", DbType.String, 256),
                new Column("PasswordFormat", DbType.Int32),
                new Column("IsApproved", DbType.Boolean),
                new Column("IsLockedOut", DbType.Boolean),
                new Column("RequiresUniqueEmail", DbType.Boolean),
                new Column("LastActivityDate", DbType.DateTime),
                new Column("ProviderUserKey", DbType.String),
                new Column("LastPasswordChangeDate", DbType.DateTime),
                new Column("LastLoginDate", DbType.DateTime),
                new Column("LastPasswordChangedDate", DbType.Date),
                new Column("LastLockoutDate", DbType.DateTime),
                new Column("FailedPasswordAttemptCount", DbType.Int32),
                new Column("FailedPasswordAttemptWindowStart", DbType.DateTime),
                new Column("FailedPasswordAnswerAttemptCount", DbType.Int32),
                new Column("FailedPasswordAnswerAttemptWindowStart", DbType.DateTime),
                new Column("Comment", DbType.String)

                );

        }

        public override void Down()
        {
            Database.RemoveTable("Membership_User");
        }
    }
}