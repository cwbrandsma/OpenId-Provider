//------------------------------------------------------------------------------
// <copyright file="SqlMembershipProvider.cs" company="Microsoft">
//     Copyright (c) Microsoft Corporation.  All rights reserved.
// </copyright>
//------------------------------------------------------------------------------

using System;
using System.Web.Security;
using System.Web;
using System.Globalization;
using System.Collections.Specialized;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Configuration.Provider;

namespace UnityMG.UnityMembershipProvider
{
    public class UnityMembershipProvider : MembershipProvider
    {
        ////////////////////////////////////////////////////////////
        // Public properties

        public override bool EnablePasswordRetrieval { get { return _enablePasswordRetrieval; } }

        public override bool EnablePasswordReset { get { return _enablePasswordReset; } }

        public override bool RequiresQuestionAndAnswer { get { return _requiresQuestionAndAnswer; } }

        public override bool RequiresUniqueEmail { get { return _requiresUniqueEmail; } }

        public override MembershipPasswordFormat PasswordFormat { get { return _passwordFormat; } }
        public override int MaxInvalidPasswordAttempts { get { return _maxInvalidPasswordAttempts; } }

        public override int PasswordAttemptWindow { get { return _passwordAttemptWindow; } }

        public override int MinRequiredPasswordLength
        {
            get { return _minRequiredPasswordLength; }
        }

        public override int MinRequiredNonAlphanumericCharacters
        {
            get { return _minRequiredNonalphanumericCharacters; }
        }

        public override string PasswordStrengthRegularExpression
        {
            get { return _passwordStrengthRegularExpression; }
        }

        public override string ApplicationName
        {
            get { return _appName; }
            set
            {
                if (String.IsNullOrEmpty(value))
                    throw new ArgumentNullException("value");

                if (value.Length > 256)
                    throw new ProviderException(SR.GetString(SR.Provider_application_name_too_long));
                _appName = value;
            }
        }

        private string _sqlConnectionString;
        private bool _enablePasswordRetrieval;
        private bool _enablePasswordReset;
        private bool _requiresQuestionAndAnswer;
        private string _appName;
        private bool _requiresUniqueEmail;
        private int _maxInvalidPasswordAttempts;
        private int _commandTimeout;
        private int _passwordAttemptWindow;
        private int _minRequiredPasswordLength;
        private int _minRequiredNonalphanumericCharacters;
        private string _passwordStrengthRegularExpression;
        private MembershipPasswordFormat _passwordFormat;

        private const int PasswordSize = 14;



        //////////////////////////////////////////////////////////////////////
        //////////////////////////////////////////////////////////////////////
        //////////////////////////////////////////////////////////////////////

        public override void Initialize(string name, NameValueCollection config)
        {
            // Remove CAS from sample: HttpRuntime.CheckAspNetHostingPermission (AspNetHostingPermissionLevel.Low, SR.Feature_not_supported_at_this_level);
            if (config == null)
                throw new ArgumentNullException("config");
            if (String.IsNullOrEmpty(name))
                name = "SqlMembershipProvider";
            if (string.IsNullOrEmpty(config["description"]))
            {
                config.Remove("description");
                config.Add("description", SR.GetString(SR.MembershipSqlProvider_description));
            }
            base.Initialize(name, config);

            _enablePasswordRetrieval = SecUtility.GetBooleanValue(config, "enablePasswordRetrieval", false);
            _enablePasswordReset = SecUtility.GetBooleanValue(config, "enablePasswordReset", true);
            _requiresQuestionAndAnswer = SecUtility.GetBooleanValue(config, "requiresQuestionAndAnswer", true);
            _requiresUniqueEmail = SecUtility.GetBooleanValue(config, "requiresUniqueEmail", true);
            _maxInvalidPasswordAttempts = SecUtility.GetIntValue(config, "maxInvalidPasswordAttempts", 5, false, 0);
            _passwordAttemptWindow = SecUtility.GetIntValue(config, "passwordAttemptWindow", 10, false, 0);
            _minRequiredPasswordLength = SecUtility.GetIntValue(config, "minRequiredPasswordLength", 7, false, 128);
            _minRequiredNonalphanumericCharacters = SecUtility.GetIntValue(config, "minRequiredNonalphanumericCharacters", 1, true, 128);

            _passwordStrengthRegularExpression = config["passwordStrengthRegularExpression"];
            if (_passwordStrengthRegularExpression != null)
            {
                _passwordStrengthRegularExpression = _passwordStrengthRegularExpression.Trim();
                if (_passwordStrengthRegularExpression.Length != 0)
                {
                    try
                    {
                        Regex regex = new Regex(_passwordStrengthRegularExpression);
                    }
                    catch (ArgumentException e)
                    {
                        throw new ProviderException(e.Message, e);
                    }
                }
            }
            else
            {
                _passwordStrengthRegularExpression = string.Empty;
            }
            if (_minRequiredNonalphanumericCharacters > _minRequiredPasswordLength)
                throw new HttpException(SR.GetString(SR.MinRequiredNonalphanumericCharacters_can_not_be_more_than_MinRequiredPasswordLength));

            _commandTimeout = SecUtility.GetIntValue(config, "commandTimeout", 30, true, 0);
            _appName = config["applicationName"];
            if (string.IsNullOrEmpty(_appName))
                _appName = SecUtility.GetDefaultAppName();

            if (_appName.Length > 256)
            {
                throw new ProviderException(SR.GetString(SR.Provider_application_name_too_long));
            }

            string strTemp = config["passwordFormat"];
            if (strTemp == null)
                strTemp = "Hashed";

            switch (strTemp)
            {
                case "Clear":
                    _passwordFormat = MembershipPasswordFormat.Clear;
                    break;
                case "Encrypted":
                    _passwordFormat = MembershipPasswordFormat.Encrypted;
                    break;
                case "Hashed":
                    _passwordFormat = MembershipPasswordFormat.Hashed;
                    break;
                default:
                    throw new ProviderException(SR.GetString(SR.Provider_bad_password_format));
            }

            if (PasswordFormat == MembershipPasswordFormat.Hashed && EnablePasswordRetrieval)
                throw new ProviderException(SR.GetString(SR.Provider_can_not_retrieve_hashed_password));
            //if (_PasswordFormat == MembershipPasswordFormat.Encrypted && MachineKeySection.IsDecryptionKeyAutogenerated)
            //    throw new ProviderException(SR.GetString(SR.Can_not_use_encrypted_passwords_with_autogen_keys));

            string temp = config["connectionStringName"];
            if (temp == null || temp.Length < 1)
                throw new ProviderException(SR.GetString(SR.Connection_name_not_specified));
            _sqlConnectionString = UserRepository.GetConnectionString(temp, true, true);
            if (_sqlConnectionString == null || _sqlConnectionString.Length < 1)
            {
                throw new ProviderException(SR.GetString(SR.Connection_string_not_found, temp));
            }

            config.Remove("connectionStringName");
            config.Remove("enablePasswordRetrieval");
            config.Remove("enablePasswordReset");
            config.Remove("requiresQuestionAndAnswer");
            config.Remove("applicationName");
            config.Remove("requiresUniqueEmail");
            config.Remove("maxInvalidPasswordAttempts");
            config.Remove("passwordAttemptWindow");
            config.Remove("commandTimeout");
            config.Remove("passwordFormat");
            config.Remove("name");
            config.Remove("minRequiredPasswordLength");
            config.Remove("minRequiredNonalphanumericCharacters");
            config.Remove("passwordStrengthRegularExpression");
            if (config.Count > 0)
            {
                string attribUnrecognized = config.GetKey(0);
                if (!String.IsNullOrEmpty(attribUnrecognized))
                    throw new ProviderException(SR.GetString(SR.Provider_unrecognized_attribute, attribUnrecognized));
            }
        }


        private int CommandTimeout
        {
            get { return _commandTimeout; }
        }

        ////////////////////////////////////////////////////////////
        ////////////////////////////////////////////////////////////
        ////////////////////////////////////////////////////////////

        public override MembershipUser CreateUser(string username,
                                                   string password,
                                                   string email,
                                                   string passwordQuestion,
                                                   string passwordAnswer,
                                                   bool isApproved,
                                                   object providerUserKey,
                                                   out    MembershipCreateStatus status)
        {
            if (!SecUtility.ValidateParameter(ref password, true, true, false, 128))
            {
                status = MembershipCreateStatus.InvalidPassword;
                return null;
            }

            string salt = GenerateSalt();
            string pass = EncodePassword(password, (int)_passwordFormat, salt);
            if (pass.Length > 128)
            {
                status = MembershipCreateStatus.InvalidPassword;
                return null;
            }

            string encodedPasswordAnswer;
            if (passwordAnswer != null)
            {
                passwordAnswer = passwordAnswer.Trim();
            }

            if (!string.IsNullOrEmpty(passwordAnswer))
            {
                if (passwordAnswer.Length > 128)
                {
                    status = MembershipCreateStatus.InvalidAnswer;
                    return null;
                }
                encodedPasswordAnswer = EncodePassword(passwordAnswer.ToLower(CultureInfo.InvariantCulture), (int)_passwordFormat, salt);
            }
            else
                encodedPasswordAnswer = passwordAnswer;
            if (!SecUtility.ValidateParameter(ref encodedPasswordAnswer, RequiresQuestionAndAnswer, true, false, 128))
            {
                status = MembershipCreateStatus.InvalidAnswer;
                return null;
            }

            if (!SecUtility.ValidateParameter(ref username, true, true, true, 256))
            {
                status = MembershipCreateStatus.InvalidUserName;
                return null;
            }

            if (!SecUtility.ValidateParameter(ref email,
                                               RequiresUniqueEmail,
                                               RequiresUniqueEmail,
                                               false,
                                               256))
            {
                status = MembershipCreateStatus.InvalidEmail;
                return null;
            }

            if (!SecUtility.ValidateParameter(ref passwordQuestion, RequiresQuestionAndAnswer, true, false, 256))
            {
                status = MembershipCreateStatus.InvalidQuestion;
                return null;
            }

            if (providerUserKey != null)
            {
                if (!(providerUserKey is Guid))
                {
                    status = MembershipCreateStatus.InvalidProviderUserKey;
                    return null;
                }
            }

            if (password.Length < MinRequiredPasswordLength)
            {
                status = MembershipCreateStatus.InvalidPassword;
                return null;
            }

            int count = 0;

            for (int i = 0; i < password.Length; i++)
            {
                if (!char.IsLetterOrDigit(password, i))
                {
                    count++;
                }
            }

            if (count < MinRequiredNonAlphanumericCharacters)
            {
                status = MembershipCreateStatus.InvalidPassword;
                return null;
            }

            if (PasswordStrengthRegularExpression.Length > 0)
            {
                if (!Regex.IsMatch(password, PasswordStrengthRegularExpression))
                {
                    status = MembershipCreateStatus.InvalidPassword;
                    return null;
                }
            }

            ValidatePasswordEventArgs e = new ValidatePasswordEventArgs(username, password, true);
            OnValidatingPassword(e);

            if (e.Cancel)
            {
                status = MembershipCreateStatus.InvalidPassword;
                return null;
            }
            DateTime dt = RoundToSeconds(DateTime.UtcNow);

            var user = new DapperUserCreate
                                        {
                                            ApplicationName = ApplicationName,
                                            UserName = username,
                                            Password = pass,
                                            Salt = salt,
                                            Email = email,
                                            PasswordQuestion = passwordQuestion,
                                            EncodedPasswordAnswer = encodedPasswordAnswer,
                                            IsApproved = isApproved,
                                            RequiresUniqueEmail = RequiresUniqueEmail,
                                            PasswordFormat = PasswordFormat,
                                            CurrentTimeUtc = dt,
                                            ProviderUserKey = providerUserKey
                                        };

            var dbo = new UserRepository(this.Name, _sqlConnectionString, CommandTimeout);
            var result = dbo.CreateUser(user);
            status = result.Status;
            return result.User;

        }

        //////////////////////////////////////////////////////////////////////
        //////////////////////////////////////////////////////////////////////
        //////////////////////////////////////////////////////////////////////

        public override bool ChangePasswordQuestionAndAnswer(string username, string password, string newPasswordQuestion, string newPasswordAnswer)
        {
            SecUtility.CheckParameter(ref username, true, true, true, 256, "username");
            SecUtility.CheckParameter(ref password, true, true, false, 128, "password");

            string salt;
            int passwordFormat;
            if (!CheckPassword(username, password, false, false, out salt, out passwordFormat))
                return false;
            SecUtility.CheckParameter(ref newPasswordQuestion, RequiresQuestionAndAnswer, RequiresQuestionAndAnswer, false, 256, "newPasswordQuestion");
            string encodedPasswordAnswer;
            if (newPasswordAnswer != null)
            {
                newPasswordAnswer = newPasswordAnswer.Trim();
            }

            SecUtility.CheckParameter(ref newPasswordAnswer, RequiresQuestionAndAnswer, RequiresQuestionAndAnswer, false, 128, "newPasswordAnswer");
            if (!string.IsNullOrEmpty(newPasswordAnswer))
            {
                encodedPasswordAnswer = EncodePassword(newPasswordAnswer.ToLower(CultureInfo.InvariantCulture), (int)passwordFormat, salt);
            }
            else
                encodedPasswordAnswer = newPasswordAnswer;
            SecUtility.CheckParameter(ref encodedPasswordAnswer, RequiresQuestionAndAnswer, RequiresQuestionAndAnswer, false, 128, "newPasswordAnswer");

            var dbo = new UserRepository(this.Name, _sqlConnectionString, CommandTimeout);
            return dbo.ChangePasswordQuestionAndAnswer(username, newPasswordQuestion, encodedPasswordAnswer);

        }

        //////////////////////////////////////////////////////////////////////
        //////////////////////////////////////////////////////////////////////
        //////////////////////////////////////////////////////////////////////

        public override string GetPassword(string username, string passwordAnswer)
        {
            throw new NotSupportedException(SR.GetString(SR.Membership_PasswordRetrieval_not_supported));
        }

        //////////////////////////////////////////////////////////////////////
        //////////////////////////////////////////////////////////////////////
        //////////////////////////////////////////////////////////////////////

        public override bool ChangePassword(string username, string oldPassword, string newPassword)
        {
            SecUtility.CheckParameter(ref username, true, true, true, 256, "username");
            SecUtility.CheckParameter(ref oldPassword, true, true, false, 128, "oldPassword");
            SecUtility.CheckParameter(ref newPassword, true, true, false, 128, "newPassword");

            string salt = null;
            int passwordFormat;

            if (!CheckPassword(username, oldPassword, false, false, out salt, out passwordFormat))
            {
                return false;
            }

            if (newPassword.Length < MinRequiredPasswordLength)
            {
                throw new ArgumentException(SR.GetString(
                              SR.Password_too_short,
                              "newPassword",
                              MinRequiredPasswordLength.ToString(CultureInfo.InvariantCulture)));
            }

            int count = 0;

            for (int i = 0; i < newPassword.Length; i++)
            {
                if (!char.IsLetterOrDigit(newPassword, i))
                {
                    count++;
                }
            }

            if (count < MinRequiredNonAlphanumericCharacters)
            {
                throw new ArgumentException(SR.GetString(
                              SR.Password_need_more_non_alpha_numeric_chars,
                              "newPassword",
                              MinRequiredNonAlphanumericCharacters.ToString(CultureInfo.InvariantCulture)));
            }

            if (PasswordStrengthRegularExpression.Length > 0)
            {
                if (!Regex.IsMatch(newPassword, PasswordStrengthRegularExpression))
                {
                    throw new ArgumentException(SR.GetString(SR.Password_does_not_match_regular_expression,
                                                             "newPassword"));
                }
            }

            string pass = EncodePassword(newPassword, passwordFormat, salt);
            if (pass.Length > 128)
            {
                throw new ArgumentException(SR.GetString(SR.Membership_password_too_long), "newPassword");
            }

            var e = new ValidatePasswordEventArgs(username, newPassword, false);
            OnValidatingPassword(e);

            if (e.Cancel)
            {
                if (e.FailureInformation != null)
                {
                    throw e.FailureInformation;
                }
                throw new ArgumentException(SR.GetString(SR.Membership_Custom_Password_Validation_Failure), "newPassword");
            }
            var dbo = new UserRepository(this.Name, _sqlConnectionString, _commandTimeout);
            return dbo.SetPassword(username, pass, salt, passwordFormat, DateTime.UtcNow);

        }

        public override string ResetPassword(string username, string passwordAnswer)
        {
            if (!EnablePasswordReset)
            {
                throw new NotSupportedException(SR.GetString(SR.Not_configured_to_support_password_resets));
            }

            SecUtility.CheckParameter(ref username, true, true, true, 256, "username");

            string salt;
            int passwordFormat;
            string passwdFromDB;
            int status;
            int failedPasswordAttemptCount;
            int failedPasswordAnswerAttemptCount;
            bool isApproved;
            DateTime lastLoginDate, lastActivityDate;

            GetPasswordWithFormat(username, false, out status, out passwdFromDB, out passwordFormat, out salt, out failedPasswordAttemptCount,
                                  out failedPasswordAnswerAttemptCount, out isApproved, out lastLoginDate, out lastActivityDate);
            if (status != 0)
            {
                if (IsStatusDueToBadPassword(status))
                {
                    throw new MembershipPasswordException(SR.GetExceptionText(status));
                }
                throw new ProviderException(SR.GetExceptionText(status));
            }

            string encodedPasswordAnswer;
            if (passwordAnswer != null)
            {
                passwordAnswer = passwordAnswer.Trim();
            }
            if (!string.IsNullOrEmpty(passwordAnswer))
                encodedPasswordAnswer = EncodePassword(passwordAnswer.ToLower(CultureInfo.InvariantCulture), passwordFormat, salt);
            else
                encodedPasswordAnswer = passwordAnswer;
            SecUtility.CheckParameter(ref encodedPasswordAnswer, RequiresQuestionAndAnswer, RequiresQuestionAndAnswer, false, 128, "passwordAnswer");
            string newPassword = GeneratePassword();

            ValidatePasswordEventArgs e = new ValidatePasswordEventArgs(username, newPassword, false);
            OnValidatingPassword(e);

            if (e.Cancel)
            {
                if (e.FailureInformation != null)
                {
                    throw e.FailureInformation;
                }
                throw new ProviderException(SR.GetString(SR.Membership_Custom_Password_Validation_Failure));
            }

            var dbo = new UserRepository(this.Name, _sqlConnectionString, _commandTimeout);
            var newpassword = EncodePassword(newPassword, passwordFormat, salt);
            if (dbo.ResetPasswordExecute(username, newpassword, passwordFormat, salt, lastActivityDate))
            {
                dbo.PasswordAttemptCountClear(username);
            }
            else
            {
                dbo.FailedPasswordAttemptIncrement(username);

                var user = dbo.GetUser(username);
                if (user.FailedPasswordAnswerAttemptCount >= MaxInvalidPasswordAttempts)
                {
                    dbo.LockAccount(username);
                }
            }
            return newpassword;
        }

        //////////////////////////////////////////////////////////////////////
        //////////////////////////////////////////////////////////////////////
        //////////////////////////////////////////////////////////////////////

        public override void UpdateUser(MembershipUser user)
        {
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }

            string temp = user.UserName;
            SecUtility.CheckParameter(ref temp, true, true, true, 256, "UserName");
            temp = user.Email;
            SecUtility.CheckParameter(ref temp,
                                       RequiresUniqueEmail,
                                       RequiresUniqueEmail,
                                       false,
                                       256,
                                       "Email");
            user.Email = temp;
            var dbo = new UserRepository(this.Name, _sqlConnectionString, _commandTimeout);
            dbo.UpdateUser(user);

        }

        //////////////////////////////////////////////////////////////////////
        //////////////////////////////////////////////////////////////////////
        //////////////////////////////////////////////////////////////////////

        public override bool ValidateUser(string username, string password)
        {
            if (SecUtility.ValidateParameter(ref username, true, true, true, 256) &&
                    SecUtility.ValidateParameter(ref password, true, true, false, 128) &&
                    CheckPassword(username, password, true, true))
            {
                // Comment out perf counters in sample: PerfCounters.IncrementCounter(AppPerfCounter.MEMBER_SUCCESS);
                // Comment out events in sample: WebBaseEvent.RaiseSystemEvent(null, WebEventCodes.AuditMembershipAuthenticationSuccess, username);
                return true;
            }
            // Comment out perf counters in sample: PerfCounters.IncrementCounter(AppPerfCounter.MEMBER_FAIL);
            // Comment out events in sample: WebBaseEvent.RaiseSystemEvent(null, WebEventCodes.AuditMembershipAuthenticationFailure, username);
            return false;
        }

        public override bool UnlockUser(string username)
        {
            SecUtility.CheckParameter(ref username, true, true, true, 256, "username");
            var dbo = new UserRepository(this.Name, _sqlConnectionString, _commandTimeout);
            var user = dbo.GetUser(username);
            if (user == null)
                return false;
            
            return dbo.UnlockAccount(username);
            
        }

        public override MembershipUser GetUser(object providerUserKey, bool userIsOnline)
        {
            if (providerUserKey == null)
            {
                throw new ArgumentNullException("providerUserKey");
            }

            if (!(providerUserKey is Guid))
            {
                throw new ArgumentException(SR.GetString(SR.Membership_InvalidProviderUserKey), "providerUserKey");
            }

            var dbo = new UserRepository(this.Name, _sqlConnectionString, _commandTimeout);
            var user = dbo.GetUserById(providerUserKey);

            if (user == null)
                return null;

            return new MembershipUser(this.Name,
                                 user.UserName,
                                 user.UserId,
                                 user.Email,
                                 user.PasswordQuestion,
                                 null,
                                 user.IsApproved,
                                 user.IsLockedOut,
                                 user.LastActivityDate,
                                 user.LastLoginDate.GetValueOrDefault(), 
                                 user.LastLoginDate.GetValueOrDefault(),
                                 user.LastPasswordChangedDate.GetValueOrDefault(),
                                 user.LastLockoutDate.GetValueOrDefault());
        }

        //////////////////////////////////////////////////////////////////////
        //////////////////////////////////////////////////////////////////////
        //////////////////////////////////////////////////////////////////////

        public override MembershipUser GetUser(string username, bool userIsOnline)
        {
            SecUtility.CheckParameter(
                            ref username,
                            true,
                            false,
                            true,
                            256,
                            "username");


            var dbo = new UserRepository(this.Name, _sqlConnectionString, _commandTimeout);
            var user = dbo.GetUser(username);

            if (user == null)
                return null;

            if (userIsOnline)
                dbo.UpdateLastActivityDate(username);

            return new MembershipUser(this.Name,
                                 user.UserName,
                                 user.UserId,
                                 user.Email,
                                 user.PasswordQuestion,
                                 null,
                                 user.IsApproved,
                                 user.IsLockedOut,
                                 user.LastActivityDate,
                                 user.LastLoginDate.GetValueOrDefault(),
                                 user.LastLoginDate.GetValueOrDefault(),
                                 user.LastPasswordChangedDate.GetValueOrDefault(),
                                 user.LastLockoutDate.GetValueOrDefault());


        }

        //////////////////////////////////////////////////////////////////////
        //////////////////////////////////////////////////////////////////////
        //////////////////////////////////////////////////////////////////////

        public override string GetUserNameByEmail(string email)
        {
            SecUtility.CheckParameter(
                            ref email,
                            false,
                            false,
                            false,
                            256,
                            "email");

            var dbo = new UserRepository(this.Name, _sqlConnectionString, _commandTimeout);
            var userName = dbo.GetUserNameByEmail(email);
            return userName;
        }

        //////////////////////////////////////////////////////////////////////
        //////////////////////////////////////////////////////////////////////
        //////////////////////////////////////////////////////////////////////

        public override bool DeleteUser(string username, bool deleteAllRelatedData)
        {
            SecUtility.CheckParameter(ref username, true, true, true, 256, "username");

            var dbo = new UserRepository(this.Name, _sqlConnectionString, _commandTimeout);
            return dbo.DeleteUser(username);

        }


        //////////////////////////////////////////////////////////////////////
        //////////////////////////////////////////////////////////////////////
        //////////////////////////////////////////////////////////////////////


        public override MembershipUserCollection GetAllUsers(int pageIndex, int pageSize, out int totalRecords)
        {
            throw new NotImplementedException();
//            if (pageIndex < 0)
//                throw new ArgumentException(SR.GetString(SR.PageIndex_bad), "pageIndex");
//            if (pageSize < 1)
//                throw new ArgumentException(SR.GetString(SR.PageSize_bad), "pageSize");
//
//            long upperBound = (long)pageIndex * pageSize + pageSize - 1;
//            if (upperBound > Int32.MaxValue)
//                throw new ArgumentException(SR.GetString(SR.PageIndex_PageSize_bad), "pageIndex and pageSize");
//
//            MembershipUserCollection users = new MembershipUserCollection();
//            totalRecords = 0;
//            try
//            {
//                SqlConnectionHolder holder = null;
//                try
//                {
//                    holder = SqlConnectionHelper.GetConnection(_sqlConnectionString, true);
//                    CheckSchemaVersion(holder.Connection);
//
//                    SqlCommand cmd = new SqlCommand("dbo.aspnet_Membership_GetAllUsers", holder.Connection);
//                    SqlDataReader reader = null;
//                    SqlParameter p = new SqlParameter("@ReturnValue", SqlDbType.Int);
//
//                    cmd.CommandTimeout = CommandTimeout;
//                    cmd.CommandType = CommandType.StoredProcedure;
//                    cmd.Parameters.Add(CreateInputParam("@ApplicationName", SqlDbType.NVarChar, ApplicationName));
//                    cmd.Parameters.Add(CreateInputParam("@PageIndex", SqlDbType.Int, pageIndex));
//                    cmd.Parameters.Add(CreateInputParam("@PageSize", SqlDbType.Int, pageSize));
//                    p.Direction = ParameterDirection.ReturnValue;
//                    cmd.Parameters.Add(p);
//                    try
//                    {
//                        reader = cmd.ExecuteReader(CommandBehavior.SequentialAccess);
//                        while (reader.Read())
//                        {
//                            string username, email, passwordQuestion, comment;
//                            bool isApproved;
//                            DateTime dtCreate, dtLastLogin, dtLastActivity, dtLastPassChange;
//                            Guid userId;
//                            bool isLockedOut;
//                            DateTime dtLastLockoutDate;
//
//                            username = GetNullableString(reader, 0);
//                            email = GetNullableString(reader, 1);
//                            passwordQuestion = GetNullableString(reader, 2);
//                            comment = GetNullableString(reader, 3);
//                            isApproved = reader.GetBoolean(4);
//                            dtCreate = reader.GetDateTime(5).ToLocalTime();
//                            dtLastLogin = reader.GetDateTime(6).ToLocalTime();
//                            dtLastActivity = reader.GetDateTime(7).ToLocalTime();
//                            dtLastPassChange = reader.GetDateTime(8).ToLocalTime();
//                            userId = reader.GetGuid(9);
//                            isLockedOut = reader.GetBoolean(10);
//                            dtLastLockoutDate = reader.GetDateTime(11).ToLocalTime();
//
//                            users.Add(new MembershipUser(this.Name,
//                                                           username,
//                                                           userId,
//                                                           email,
//                                                           passwordQuestion,
//                                                           comment,
//                                                           isApproved,
//                                                           isLockedOut,
//                                                           dtCreate,
//                                                           dtLastLogin,
//                                                           dtLastActivity,
//                                                           dtLastPassChange,
//                                                           dtLastLockoutDate));
//                        }
//                    }
//                    finally
//                    {
//                        if (reader != null)
//                            reader.Close();
//                        if (p.Value != null && p.Value is int)
//                            totalRecords = (int)p.Value;
//                    }
//                }
//                finally
//                {
//                    if (holder != null)
//                    {
//                        holder.Close();
//                        holder = null;
//                    }
//                }
//            }
//            catch
//            {
//                throw;
//            }
//            return users;
        }
        /////////////////////////////////////////////////////////////////////////////
        /////////////////////////////////////////////////////////////////////////////
        /////////////////////////////////////////////////////////////////////////////

        public override int GetNumberOfUsersOnline()
        {
            throw new NotImplementedException();
        }

        /////////////////////////////////////////////////////////////////////////////
        /////////////////////////////////////////////////////////////////////////////
        /////////////////////////////////////////////////////////////////////////////

        public override MembershipUserCollection FindUsersByName(string usernameToMatch, int pageIndex, int pageSize, out int totalRecords)
        {
            throw new NotImplementedException();
//            SecUtility.CheckParameter(ref usernameToMatch, true, true, false, 256, "usernameToMatch");
//
//            if (pageIndex < 0)
//                throw new ArgumentException(SR.GetString(SR.PageIndex_bad), "pageIndex");
//            if (pageSize < 1)
//                throw new ArgumentException(SR.GetString(SR.PageSize_bad), "pageSize");
//
//            long upperBound = (long)pageIndex * pageSize + pageSize - 1;
//            if (upperBound > Int32.MaxValue)
//                throw new ArgumentException(SR.GetString(SR.PageIndex_PageSize_bad), "pageIndex and pageSize");
//
//            try
//            {
//                SqlConnectionHolder holder = null;
//                totalRecords = 0;
//                SqlParameter p = new SqlParameter("@ReturnValue", SqlDbType.Int);
//                p.Direction = ParameterDirection.ReturnValue;
//                try
//                {
//                    holder = SqlConnectionHelper.GetConnection(_sqlConnectionString, true);
//                    CheckSchemaVersion(holder.Connection);
//
//                    SqlCommand cmd = new SqlCommand("dbo.aspnet_Membership_FindUsersByName", holder.Connection);
//                    MembershipUserCollection users = new MembershipUserCollection();
//                    SqlDataReader reader = null;
//
//                    cmd.CommandTimeout = CommandTimeout;
//                    cmd.CommandType = CommandType.StoredProcedure;
//                    cmd.Parameters.Add(CreateInputParam("@ApplicationName", SqlDbType.NVarChar, ApplicationName));
//                    cmd.Parameters.Add(CreateInputParam("@UserNameToMatch", SqlDbType.NVarChar, usernameToMatch));
//                    cmd.Parameters.Add(CreateInputParam("@PageIndex", SqlDbType.Int, pageIndex));
//                    cmd.Parameters.Add(CreateInputParam("@PageSize", SqlDbType.Int, pageSize));
//                    cmd.Parameters.Add(p);
//                    try
//                    {
//                        reader = cmd.ExecuteReader(CommandBehavior.SequentialAccess);
//                        while (reader.Read())
//                        {
//                            string username, email, passwordQuestion, comment;
//                            bool isApproved;
//                            DateTime dtCreate, dtLastLogin, dtLastActivity, dtLastPassChange;
//                            Guid userId;
//                            bool isLockedOut;
//                            DateTime dtLastLockoutDate;
//
//                            username = GetNullableString(reader, 0);
//                            email = GetNullableString(reader, 1);
//                            passwordQuestion = GetNullableString(reader, 2);
//                            comment = GetNullableString(reader, 3);
//                            isApproved = reader.GetBoolean(4);
//                            dtCreate = reader.GetDateTime(5).ToLocalTime();
//                            dtLastLogin = reader.GetDateTime(6).ToLocalTime();
//                            dtLastActivity = reader.GetDateTime(7).ToLocalTime();
//                            dtLastPassChange = reader.GetDateTime(8).ToLocalTime();
//                            userId = reader.GetGuid(9);
//                            isLockedOut = reader.GetBoolean(10);
//                            dtLastLockoutDate = reader.GetDateTime(11).ToLocalTime();
//
//                            users.Add(new MembershipUser(this.Name,
//                                                           username,
//                                                           userId,
//                                                           email,
//                                                           passwordQuestion,
//                                                           comment,
//                                                           isApproved,
//                                                           isLockedOut,
//                                                           dtCreate,
//                                                           dtLastLogin,
//                                                           dtLastActivity,
//                                                           dtLastPassChange,
//                                                           dtLastLockoutDate));
//                        }
//
//                        return users;
//                    }
//                    finally
//                    {
//                        if (reader != null)
//                            reader.Close();
//                        if (p.Value != null && p.Value is int)
//                            totalRecords = (int)p.Value;
//                    }
//                }
//                finally
//                {
//                    if (holder != null)
//                    {
//                        holder.Close();
//                        holder = null;
//                    }
//                }
//            }
//            catch
//            {
//                throw;
//            }
        }
        /////////////////////////////////////////////////////////////////////////////
        /////////////////////////////////////////////////////////////////////////////
        /////////////////////////////////////////////////////////////////////////////
        public override MembershipUserCollection FindUsersByEmail(string emailToMatch, int pageIndex, int pageSize, out int totalRecords)
        {
            throw new NotImplementedException();
//            SecUtility.CheckParameter(ref emailToMatch, false, false, false, 256, "emailToMatch");
//
//            if (pageIndex < 0)
//                throw new ArgumentException(SR.GetString(SR.PageIndex_bad), "pageIndex");
//            if (pageSize < 1)
//                throw new ArgumentException(SR.GetString(SR.PageSize_bad), "pageSize");
//
//            long upperBound = (long)pageIndex * pageSize + pageSize - 1;
//            if (upperBound > Int32.MaxValue)
//                throw new ArgumentException(SR.GetString(SR.PageIndex_PageSize_bad), "pageIndex and pageSize");
//
//            try
//            {
//                SqlConnectionHolder holder = null;
//                totalRecords = 0;
//                SqlParameter p = new SqlParameter("@ReturnValue", SqlDbType.Int);
//                p.Direction = ParameterDirection.ReturnValue;
//                try
//                {
//                    holder = SqlConnectionHelper.GetConnection(_sqlConnectionString, true);
//                    CheckSchemaVersion(holder.Connection);
//
//                    SqlCommand cmd = new SqlCommand("dbo.aspnet_Membership_FindUsersByEmail", holder.Connection);
//                    MembershipUserCollection users = new MembershipUserCollection();
//                    SqlDataReader reader = null;
//
//                    cmd.CommandTimeout = CommandTimeout;
//                    cmd.CommandType = CommandType.StoredProcedure;
//                    cmd.Parameters.Add(CreateInputParam("@ApplicationName", SqlDbType.NVarChar, ApplicationName));
//                    cmd.Parameters.Add(CreateInputParam("@EmailToMatch", SqlDbType.NVarChar, emailToMatch));
//                    cmd.Parameters.Add(CreateInputParam("@PageIndex", SqlDbType.Int, pageIndex));
//                    cmd.Parameters.Add(CreateInputParam("@PageSize", SqlDbType.Int, pageSize));
//                    cmd.Parameters.Add(p);
//                    try
//                    {
//                        reader = cmd.ExecuteReader(CommandBehavior.SequentialAccess);
//                        while (reader.Read())
//                        {
//                            string username, email, passwordQuestion, comment;
//                            bool isApproved;
//                            DateTime dtCreate, dtLastLogin, dtLastActivity, dtLastPassChange;
//                            Guid userId;
//                            bool isLockedOut;
//                            DateTime dtLastLockoutDate;
//
//                            username = GetNullableString(reader, 0);
//                            email = GetNullableString(reader, 1);
//                            passwordQuestion = GetNullableString(reader, 2);
//                            comment = GetNullableString(reader, 3);
//                            isApproved = reader.GetBoolean(4);
//                            dtCreate = reader.GetDateTime(5).ToLocalTime();
//                            dtLastLogin = reader.GetDateTime(6).ToLocalTime();
//                            dtLastActivity = reader.GetDateTime(7).ToLocalTime();
//                            dtLastPassChange = reader.GetDateTime(8).ToLocalTime();
//                            userId = reader.GetGuid(9);
//                            isLockedOut = reader.GetBoolean(10);
//                            dtLastLockoutDate = reader.GetDateTime(11).ToLocalTime();
//
//                            users.Add(new MembershipUser(this.Name,
//                                                           username,
//                                                           userId,
//                                                           email,
//                                                           passwordQuestion,
//                                                           comment,
//                                                           isApproved,
//                                                           isLockedOut,
//                                                           dtCreate,
//                                                           dtLastLogin,
//                                                           dtLastActivity,
//                                                           dtLastPassChange,
//                                                           dtLastLockoutDate));
//                        }
//
//                        return users;
//                    }
//                    finally
//                    {
//                        if (reader != null)
//                            reader.Close();
//                        if (p.Value != null && p.Value is int)
//                            totalRecords = (int)p.Value;
//                    }
//                }
//                finally
//                {
//                    if (holder != null)
//                    {
//                        holder.Close();
//                        holder = null;
//                    }
//                }
//            }
//            catch
//            {
//                throw;
//            }
        }

        /////////////////////////////////////////////////////////////////////////////
        /////////////////////////////////////////////////////////////////////////////
        private bool CheckPassword(string username, string password, bool updateLastLoginActivityDate, bool failIfNotApproved)
        {
            string salt;
            int passwordFormat;
            return CheckPassword(username, password, updateLastLoginActivityDate, failIfNotApproved, out salt, out passwordFormat);
        }

        private bool CheckPassword(string username, string password, bool updateLastLoginActivityDate, bool failIfNotApproved, out string salt, out int passwordFormat)
        {
            string passwdFromDB;
            int status;
            int failedPasswordAttemptCount;
            int failedPasswordAnswerAttemptCount;
            bool isApproved;
            DateTime lastLoginDate, lastActivityDate;

            GetPasswordWithFormat(username, updateLastLoginActivityDate, out status, out passwdFromDB, out passwordFormat, out salt, out failedPasswordAttemptCount,
                                  out failedPasswordAnswerAttemptCount, out isApproved, out lastLoginDate, out lastActivityDate);
            if (status != 0)
                return false;
            if (!isApproved && failIfNotApproved)
                return false;

            string encodedPasswd = EncodePassword(password, passwordFormat, salt);

            bool isPasswordCorrect = passwdFromDB.Equals(encodedPasswd);

            if (isPasswordCorrect && failedPasswordAttemptCount == 0 && failedPasswordAnswerAttemptCount == 0)
                return true;


            var dbo = new UserRepository(this.Name, _sqlConnectionString, _commandTimeout);
            var user = dbo.GetUser(username);

            // set out parameters
            passwordFormat = (int)user.PasswordFormat;
            salt = user.Salt;
            if (user.IsLockedOut)
                return false;

           DateTime dtNow = DateTime.UtcNow;

            if (!isPasswordCorrect)
            {
                user.FailedPasswordAnswerAttemptWindowStart = user.FailedPasswordAnswerAttemptWindowStart ?? DateTime.UtcNow.AddYears(-2);
                if (dtNow > user.FailedPasswordAnswerAttemptWindowStart.Value.AddMinutes(_passwordAttemptWindow))
                {
                    dbo.PasswordAttemptCountClear(username);
                }
                dbo.FailedPasswordAttemptIncrement(username);
                
                if (user.FailedPasswordAnswerAttemptCount.GetValueOrDefault() >= failedPasswordAnswerAttemptCount)
                {
                    dbo.LockAccount(username);
                }
            }
            else
            {
                if (user.FailedPasswordAnswerAttemptCount.GetValueOrDefault() > 0 || user.FailedPasswordAnswerAttemptCount.GetValueOrDefault() > 0)
                {
                    dbo.UnlockAccount(username);
                }
            }

            dbo.UpdateLastActivityDate(username);


            return isPasswordCorrect;
        }

        /////////////////////////////////////////////////////////////////////////////
        /////////////////////////////////////////////////////////////////////////////
        private void GetPasswordWithFormat(string username,
                                            bool updateLastLoginActivityDate,
                                            out int status,
                                            out string password,
                                            out int passwordFormat,
                                            out string passwordSalt,
                                            out int failedPasswordAttemptCount,
                                            out int failedPasswordAnswerAttemptCount,
                                            out bool isApproved,
                                            out DateTime lastLoginDate,
                                            out DateTime lastActivityDate)
        {

            var dbo = new UserRepository(this.Name, _sqlConnectionString, _commandTimeout);
            var user = dbo.GetUser(username);

            status = -1;
            password = null;
            passwordFormat = 0;
            passwordSalt = null;
            failedPasswordAttemptCount = 0;
            failedPasswordAnswerAttemptCount = 0;
            isApproved = false;
            lastLoginDate = DateTime.UtcNow;
            lastActivityDate = DateTime.UtcNow;

            if (user == null)
            {
                return;
            }
            if (user.IsLockedOut)
            {
                status = 99;
                return;
            }

            status = 0;
            password = user.Password;
            passwordFormat = (int)user.PasswordFormat;
            passwordSalt = user.Salt;
            failedPasswordAttemptCount = user.FailedPasswordAttemptCount.GetValueOrDefault();
            failedPasswordAnswerAttemptCount = user.FailedPasswordAnswerAttemptCount.GetValueOrDefault();
            isApproved = user.IsApproved;
            lastLoginDate = user.LastLoginDate.GetValueOrDefault();
            lastActivityDate = user.LastActivityDate;

            if (updateLastLoginActivityDate)
            {
                dbo.UpdateLastActivityDate(username);
                lastLoginDate = DateTime.UtcNow;
                lastActivityDate = DateTime.UtcNow;

            }
        }


        /////////////////////////////////////////////////////////////////////////////
        /////////////////////////////////////////////////////////////////////////////

        public virtual string GeneratePassword()
        {
            return Membership.GeneratePassword(
                      MinRequiredPasswordLength < PasswordSize ? PasswordSize : MinRequiredPasswordLength,
                      MinRequiredNonAlphanumericCharacters);
        }

        private bool IsStatusDueToBadPassword(int status)
        {
            return (status >= 2 && status <= 6 || status == 99);
        }

        private DateTime RoundToSeconds(DateTime dt)
        {
            return new DateTime(dt.Year, dt.Month, dt.Day, dt.Hour, dt.Minute, dt.Second);
        }
        internal string GenerateSalt()
        {
            byte[] buf = new byte[16];
            (new RNGCryptoServiceProvider()).GetBytes(buf);
            return Convert.ToBase64String(buf);
        }

        private HashAlgorithm GetHashAlgorithm()
        {
            HashAlgorithm s = HashAlgorithm.Create(Membership.HashAlgorithmType);
            return s;
        }

        internal string EncodePassword(string pass, int passwordFormat, string salt)
        {
            if (passwordFormat == 0)
                return pass;
            byte[] bytes = Encoding.Unicode.GetBytes(pass);
            byte[] numArray1 = Convert.FromBase64String(salt);
            byte[] inArray;
            if (passwordFormat == 1)
            {
                HashAlgorithm hashAlgorithm = this.GetHashAlgorithm();
                if (hashAlgorithm is KeyedHashAlgorithm)
                {
                    var keyedHashAlgorithm = (KeyedHashAlgorithm)hashAlgorithm;
                    if (keyedHashAlgorithm.Key.Length == numArray1.Length)
                        keyedHashAlgorithm.Key = numArray1;
                    else if (keyedHashAlgorithm.Key.Length < numArray1.Length)
                    {
                        byte[] numArray2 = new byte[keyedHashAlgorithm.Key.Length];
                        Buffer.BlockCopy((Array)numArray1, 0, (Array)numArray2, 0, numArray2.Length);
                        keyedHashAlgorithm.Key = numArray2;
                    }
                    else
                    {
                        byte[] numArray2 = new byte[keyedHashAlgorithm.Key.Length];
                        int dstOffset = 0;
                        while (dstOffset < numArray2.Length)
                        {
                            int count = Math.Min(numArray1.Length, numArray2.Length - dstOffset);
                            Buffer.BlockCopy((Array)numArray1, 0, (Array)numArray2, dstOffset, count);
                            dstOffset += count;
                        }
                        keyedHashAlgorithm.Key = numArray2;
                    }
                    inArray = keyedHashAlgorithm.ComputeHash(bytes);
                }
                else
                {
                    byte[] buffer = new byte[numArray1.Length + bytes.Length];
                    Buffer.BlockCopy((Array)numArray1, 0, (Array)buffer, 0, numArray1.Length);
                    Buffer.BlockCopy((Array)bytes, 0, (Array)buffer, numArray1.Length, bytes.Length);
                    inArray = hashAlgorithm.ComputeHash(buffer);
                }
            }
            else
            {
                inArray = EncryptPassword(bytes);
            }
            return Convert.ToBase64String(inArray);
        }

        internal string UnEncodePassword(string pass, int passwordFormat)
        {
            switch (passwordFormat)
            {
                case 0: // MembershipPasswordFormat.Clear:
                    return pass;
                case 1: // MembershipPasswordFormat.Hashed:
                    throw new ProviderException(SR.GetString(SR.Provider_can_not_decode_hashed_password));
                default:
                    byte[] bIn = Convert.FromBase64String(pass);
                    byte[] bRet = DecryptPassword(bIn);
                    if (bRet == null)
                        return null;
                    return Encoding.Unicode.GetString(bRet, 16, bRet.Length - 16);
            }
        }

        public string GetSalt(string username)
        {
            var dbo = new UserRepository(this.Name, _sqlConnectionString, CommandTimeout);
            var user = dbo.GetUser(username);
            return user.Salt;
        }
    }
}
