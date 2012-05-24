using System;
using System.Collections.Generic;
using System.Configuration;
using System.Data;
using System.Data.SqlClient;
using System.Linq;
using System.Web.Security;
using Dapper;

namespace UnityMG.UnityMembershipProvider
{
    public class UserRepository
    {
        private readonly string _providerName;
        private readonly string _sqlConnectionString;
        private readonly int? _commandTimeout;
        private const string SqlGetIdentity = "SELECT SCOPE_IDENTITY()";

        public UserRepository(string providerName, string sqlConnectionString, int? commandTimeout)
        {
            _providerName = providerName;
            _sqlConnectionString = sqlConnectionString;
            _commandTimeout = commandTimeout;
        }

        public static string GetConnectionString(string specifiedConnectionString, bool lookupConnectionString, bool appLevel)
        {
            if (specifiedConnectionString == null || specifiedConnectionString.Length < 1)
                return null;

            string connectionString = null;

            /////////////////////////////////////////
            // Step 1: Check <connectionStrings> config section for this connection string
            if (lookupConnectionString)
            {
                ConnectionStringSettings connObj = ConfigurationManager.ConnectionStrings[specifiedConnectionString];
                if (connObj != null)
                    connectionString = connObj.ConnectionString;

                if (connectionString == null)
                    return null;
            }
            else
            {
                connectionString = specifiedConnectionString;
            }

            return connectionString;
        }
    

        private System.Data.Common.DbConnection CreateConnection(string connectionString)
        {
            var conn = new SqlConnection(connectionString);
            conn.Open();
            return conn;
        } 

        public DapperUserRequest GetUser(string username)
        {
            const string sql =
                "SELECT UserId, UserName, Password, Salt, PasswordFormat, Email, PasswordQuestion, PasswordAnswer, IsApproved, IsLockedOut, PasswordFormat, LastActivityDate, LastLoginDate, LastPasswordChangedDate FROM Membership_User WHERE UserName = @username";

            return QuerySingle<DapperUserRequest>(sql, new {username});
        }

        public DapperUserRequest GetUserById(object userId)
        {
            const string sql =
                "SELECT UserId, UserName, Password, Salt, PasswordFormat, Email, PasswordQuestion, PasswordAnswer, IsApproved, IsLockedOut, PasswordFormat, LastActivityDate, LastLoginDate, LastPasswordChangedDate FROM Membership_User WHERE UserId = @userId";

            return QuerySingle<DapperUserRequest>(sql, new { userId });
        }

        internal class UserEmail
        {
            public string UserName { get; set; }
        }

        public string GetUserNameByEmail(string email)
        {
            const string sql =
                "SELECT UserName FROM Membership_User WHERE email = @email";


            var result = QuerySingle<UserEmail>(sql, new { email });
            if (result == null)
                return string.Empty;
            return result.UserName;
        }

        
        public DapperUserCreated CreateUser(DapperUserCreate user)
        {
            var result = new DapperUserCreated();

            const string sql =
                "INSERT INTO Membership_User (UserId, UserName, Password, Salt, Email, PasswordQuestion, PasswordAnswer, IsApproved, PasswordFormat, LastActivityDate) " +
                "VALUES (@userId, @userName, @password, @passwordSalt, @email, @passwordQuestion, @passwordAnswer, @isApproved, @passwordFormat, @currentTimeUtc)";



            using (var conn = CreateConnection(_sqlConnectionString))
            {
                Guid userId = Guid.NewGuid();
                using (var trans = conn.BeginTransaction())
                {
                    try
                    {
                        var value = conn.Execute(sql, new
                                                          {
                                                              userId = userId,
                                                              userName = user.UserName,
                                                              password = user.Password,
                                                              passwordSalt = user.Salt,
                                                              email = user.Email,
                                                              passwordQuestion = user.PasswordQuestion,
                                                              passwordAnswer = user.EncodedPasswordAnswer,
                                                              isApproved = user.IsApproved,
                                                              passwordFormat = user.PasswordFormat,
                                                              currentTimeUtc = user.CurrentTimeUtc
                                                          }, trans, commandTimeout: _commandTimeout);


//                        userId = conn.Query<Guid>(SqlGetIdentity, trans).FirstOrDefault();

                        trans.Commit();

                        if (value > 0)
                            result.Status = MembershipCreateStatus.Success;
                        else
                            result.Status = MembershipCreateStatus.ProviderError;
                    }
                    catch (Exception ex)
                    {
                        result.Status = MembershipCreateStatus.ProviderError;
                        return result;
                    }

                }
                var dt = user.CurrentTimeUtc;
                result.User = new MembershipUser(_providerName,
                                                 user.UserName,
                                                 userId,
                                                 user.Email,
                                                 user.PasswordQuestion,
                                                 null,
                                                 user.IsApproved,
                                                 false,
                                                 dt,
                                                 dt,
                                                 dt,
                                                 dt,
                                                 new DateTime(1754, 1, 1));
                return result;
            }
        }


        public bool ChangePasswordQuestionAndAnswer(string username, string newPasswordQuestion,
                                                    string encodedPasswordAnswer)
        {
            const string sql =
                "UPDATE Membership_User SET (PasswordQuestion = @question, PasswordAnswer = @answer) WHERE username = @username";
            var data = new
                           {
                               userName = username,
                               passwordQuestion = newPasswordQuestion,
                               passwordAnswer = encodedPasswordAnswer,
                           };
            return Execute(sql, data);

        }

        public string GetPasswordFromDb(string username, string passwordAnswer, bool requiresQuestionAndAnswer,
                                        out int passwordFormat, out int status)
        {
            var user = GetUser(username);

            if (user.IsLockedOut)
            {
                status = -1;
                passwordFormat = 0;
                return null;
            }

            status = 1;
            passwordFormat = (int) user.PasswordFormat;
            return user.Password;

        }

        public bool SetPassword(string username, string pass, string salt, int passwordFormat, DateTime utcNow)
        {
            var user = GetUser(username);
            if (user == null) return false;

            const string sql =
                @"UPDATE Membership_User
    SET Password = @NewPassword, PasswordFormat = @PasswordFormat, PasswordSalt = @PasswordSalt,
        LastPasswordChangedDate = @LastActivityDate
    WHERE @username = username";

            var data = new
                           {
                               username = username,
                               NewPassword = pass,
                               PasswordFormat = passwordFormat,
                               PasswordSalt = salt,
                               CurrentTimeUtc = utcNow,
                           };

            return Execute(sql, data);
        }


        public bool ResetPasswordExecute(string username, string newpassword, int passwordFormat, string salt, DateTime utcNow)
        {
            const string sql =
    @"UPDATE Membership_User
    SET    Password = @NewPassword,
           LastPasswordChangedDate = @LastActivityDate,
           PasswordFormat = @PasswordFormat,
           PasswordSalt = @PasswordSalt
    WHERE  @username = username";

            var data = new
                           {
                               username = username,
                               NewPassword = newpassword,
                               PasswordFormat = passwordFormat,
                               PasswordSalt = salt,
                               CurrentTimeUtc = utcNow,
                           };
            return Execute(sql, data);

        }


        public void PasswordAttemptCountClear(string username)
        {
            const string sql =
@"UPDATE Membership_User
    SET    FailedPasswordAnswerAttemptCount = 0,
           FailedPasswordAnswerAttemptWindowStart = @date
    WHERE  @username = username";
            DateTime? dt = null;
            var data = new
                           {
                               username = username,
                               date = dt,
                           };

            Execute(sql, data);
        }

        public void FailedPasswordAttemptIncrement(string username)
        {
            const string sql =
@"UPDATE Membership_User
    SET    FailedPasswordAnswerAttemptCount = FailedPasswordAnswerAttemptCount + 1,
           FailedPasswordAnswerAttemptWindowStart = @date
    WHERE  @username = username";

            Execute(sql, new
                             {
                                 username = username,
                                 date = DateTime.UtcNow,
                             });
        }

        private T QuerySingle<T>(string sql, dynamic param = null)
        {
            using (var conn = CreateConnection(_sqlConnectionString))
            {
                var result = SqlMapper.Query<T>(conn, sql, param, commandTimeout: _commandTimeout);
                return ((IList<T>) result).FirstOrDefault();
            }
        }

        private bool Execute(string sql, dynamic param = null )
        {
            using (var conn = CreateConnection(_sqlConnectionString))
            {
                using (var trans = conn.BeginTransaction())
                {
                    try
                    {
                        var result = SqlMapper.Execute( conn, sql, param, trans);
                        trans.Commit();
                        return true;
                    }
                    catch (Exception ex)
                    {
                        trans.Rollback();
                        throw;
                    }
                }
            }

        }

        public bool LockAccount(string username)
        {
            const string sql =
@"UPDATE Membership_User
    SET    IsLockedOut = 1,
           LastLockoutDate = @date
    WHERE  @username = username";

            var data = new
                           {
                               username = username,
                               date = DateTime.UtcNow,
                           };
            return Execute(sql, data);
        }

        public bool UnlockAccount(string username)
        {
            const string sql =
                @"UPDATE Membership_User
    SET IsLockedOut = 0,
        FailedPasswordAttemptCount = 0,
        FailedPasswordAttemptWindowStart = @date,
        FailedPasswordAnswerAttemptCount = 0,
        FailedPasswordAnswerAttemptWindowStart = @date,
        LastLockoutDate = @date
    WHERE username = @username";

            DateTime? dt = null;

            var data = new
            {
                UserId = username,
                date = dt,
            };
            return Execute(sql, data);
        }


        public void UpdateUser(MembershipUser user)
        {
            const string sql =
    @"UPDATE Membership_User
    SET IsLockedOut = 0,
        LastActivityDate = @date,
        Email = @email,
        IsApproved = @isApproved,
        LastLoginDate = @date
    WHERE UserId = @UserId";

            DateTime? dt = DateTime.UtcNow;

            var data = new
            {
                UserId = user.ProviderUserKey,
                date = dt,
                email = user.Email,
                isApproved = user.IsApproved,

            };
            Execute(sql, data);

            
        }

        public void UpdateLastActivityDate(string username)
        {
            const string sql =
                @"UPDATE Membership_User
    SET LastActivityDate = @date
    WHERE UserName = @username";

            DateTime? dt = DateTime.UtcNow;

            var data = new
            {
                Username = username,
                date = dt,
            };
            Execute(sql, data);
        }

        public bool DeleteUser(string username)
        {
            const string sql =
                @"DELETE FROM Membership_User
    WHERE UserName = @username";

            var data = new
            {
                username = username,
            };
            return Execute(sql, data);
        }
    }

    public class DapperUserCreate
    {
        public string ApplicationName { get; set; }
        public string UserName { get; set; }
        public string Password { get; set; }
        public string Salt { get; set; }
        public string Email { get; set; }
        public string PasswordQuestion { get; set; }
        public string EncodedPasswordAnswer { get; set; }
        public bool IsApproved { get; set; }
        public bool RequiresUniqueEmail { get; set; }
        public MembershipPasswordFormat PasswordFormat { get; set; }
        public DateTime CurrentTimeUtc { get; set; }
        public object ProviderUserKey { get; set; }
    }

    public class DapperUserCreated
    {
        public MembershipCreateStatus Status { get; set; }
        public MembershipUser User { get; set; }
    }

    public class DapperUserRequest
    {
        public Guid UserId { get; set; }
        public string UserName { get; set; }
        public string Password { get; set; }
        public string Salt { get; set; }
        public string Email { get; set; }
        public string PasswordQuestion { get; set; }
        public string EncodedPasswordAnswer { get; set; }
        public bool IsApproved { get; set; }
        public bool RequiresUniqueEmail { get; set; }
        public MembershipPasswordFormat PasswordFormat { get; set; }
        public DateTime? LastLoginDate { get; set; }
        public DateTime? LastPasswordChangedDate { get; set; }
        public DateTime LastActivityDate { get; set; }
        public object ProviderUserKey { get; set; }
        public bool IsLockedOut { get; set; }
        public DateTime? LastLockoutDate { get; set; }
        public int? FailedPasswordAttemptCount { get; set; }
        public DateTime? FailedPasswordAttemptWindowStart { get; set; }
        public int? FailedPasswordAnswerAttemptCount { get; set; }
        public DateTime? FailedPasswordAnswerAttemptWindowStart { get; set; }

    }

}