import 'dart:convert';
import 'dart:io' show Platform;

import 'package:flutter/foundation.dart' show kIsWeb;
import 'package:flutter/material.dart';
import 'package:http/http.dart' as http;
import 'package:shared_preferences/shared_preferences.dart';

import 'homepage.dart';

class LoginPage extends StatefulWidget {
  const LoginPage({super.key});

  @override
  State<LoginPage> createState() => LoginPageState();
}

String getBaseUrl() {
  if (kIsWeb) {
    final host = Uri.base.host;
    return "http://$host:5000";
  }

  if (Platform.isWindows) return "http://127.0.0.1:5000";

  return "http://192.168.0.102:5000";
}

class LoginPageState extends State<LoginPage> {
  final formKey = GlobalKey<FormState>();
  final e = TextEditingController();
  final p = TextEditingController();

  bool isLoading = false;
  String errorMessage = '';

  @override
  void dispose() {
    e.dispose();
    p.dispose();
    super.dispose();
  }

  Future<void> login() async {
    if (!formKey.currentState!.validate()) return;

    setState(() {
      isLoading = true;
      errorMessage = '';
    });

    final baseUrl = getBaseUrl();
    final url = Uri.parse("$baseUrl/api/mobile/login");

    try {
      final response = await http
          .post(
            url,
            headers: {"Content-Type": "application/json"},
            body: jsonEncode({
              "email": e.text.trim(),
              "password": p.text,
            }),
          )
          .timeout(const Duration(seconds: 10));

      Map<String, dynamic> data;
      try {
        data = jsonDecode(response.body) as Map<String, dynamic>;
      } catch (err) {
        setState(() {
          errorMessage = "Server returned invalid JSON (${response.statusCode})";
        });
        return;
      }

      if (response.statusCode == 200 && data["token"] != null) {
        final prefs = await SharedPreferences.getInstance();
        await prefs.setString("token", data["token"]);

        if (!mounted) return;

        Navigator.pushReplacement(
          context,
          MaterialPageRoute(
            builder: (_) => Homepage(user: data["user"]),
          ),
        );
      } else {
        setState(() {
          errorMessage = data["error"] ?? "Login failed";
        });
      }
    } catch (err) {
      setState(() {
        errorMessage = "Cannot connect to server: $err";
      });
    } finally {
      if (mounted) {
        setState(() => isLoading = false);
      }
    }
  }

  InputDecoration _inputDecoration({
    required String hint,
    required IconData icon,
  }) {
    return InputDecoration(
      hintText: hint,
      hintStyle: const TextStyle(
        color: Color(0xFF6A6F87),
        fontSize: 17,
        fontWeight: FontWeight.w500,
      ),
      prefixIcon: Icon(
        icon,
        color: const Color(0xFF6A6F87),
        size: 30,
      ),
      filled: true,
      fillColor: Colors.white.withOpacity(0.92),
      contentPadding: const EdgeInsets.symmetric(
        horizontal: 20,
        vertical: 22,
      ),
      border: OutlineInputBorder(
        borderRadius: BorderRadius.circular(22),
        borderSide: BorderSide.none,
      ),
      enabledBorder: OutlineInputBorder(
        borderRadius: BorderRadius.circular(22),
        borderSide: BorderSide.none,
      ),
      focusedBorder: OutlineInputBorder(
        borderRadius: BorderRadius.circular(22),
        borderSide: const BorderSide(
          color: Color(0xFF3E56A6),
          width: 1.2,
        ),
      ),
      errorBorder: OutlineInputBorder(
        borderRadius: BorderRadius.circular(22),
        borderSide: const BorderSide(
          color: Colors.red,
          width: 1.2,
        ),
      ),
      focusedErrorBorder: OutlineInputBorder(
        borderRadius: BorderRadius.circular(22),
        borderSide: const BorderSide(
          color: Colors.red,
          width: 1.2,
        ),
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      resizeToAvoidBottomInset: true,
      body: Stack(
        children: [
          Positioned.fill(
            child: Image.asset(
              'assets/img3.png',
              fit: BoxFit.cover,
            ),
          ),
          SafeArea(
            child: Center(
              child: SingleChildScrollView(
                padding: const EdgeInsets.symmetric(horizontal: 30, vertical: 20),
                child: ConstrainedBox(
                  constraints: const BoxConstraints(maxWidth: 430),
                  child: Form(
                    key: formKey,
                    child: Column(
                      children: [
                        const SizedBox(height: 25),
                        SizedBox(
                          height: 250,
                          child: OverflowBox(
                            alignment: Alignment.center,
                            maxHeight: 360,
                            child: Image.asset(
                              'assets/img4.png',
                              height: 360,
                            ),
                          ),
                        ),
                        const SizedBox(height: 26),
                        const Text(
                          "Welcome Back",
                          textAlign: TextAlign.center,
                          style: TextStyle(
                            fontSize: 34,
                            fontWeight: FontWeight.w800,
                            color: Color(0xFF2B3771),
                          ),
                        ),
                        const SizedBox(height: 8),
                        const Text(
                          "Sign in to continue",
                          textAlign: TextAlign.center,
                          style: TextStyle(
                            fontSize: 17,
                            color: Color(0xFF6F748A),
                            fontWeight: FontWeight.w500,
                          ),
                        ),
                        const SizedBox(height: 34),

                        TextFormField(
                          controller: e,
                          style: const TextStyle(
                            fontSize: 17,
                            color: Color(0xFF2B2B2B),
                          ),
                          decoration: _inputDecoration(
                            hint: "Email Address",
                            icon: Icons.email_outlined,
                          ),
                          validator: (value) {
                            if (value == null || value.isEmpty) {
                              return 'Please enter your email';
                            }
                            if (!value.contains('@')) {
                              return 'Please enter a valid email';
                            }
                            return null;
                          },
                        ),
                        const SizedBox(height: 18),

                        TextFormField(
                          controller: p,
                          obscureText: true,
                          style: const TextStyle(
                            fontSize: 17,
                            color: Color(0xFF2B2B2B),
                          ),
                          decoration: _inputDecoration(
                            hint: "Password",
                            icon: Icons.lock_outline,
                          ),
                          validator: (value) {
                            if (value == null || value.isEmpty) {
                              return 'Please enter your password';
                            }
                            return null;
                          },
                        ),
                        const SizedBox(height: 28),

                        SizedBox(
                          width: double.infinity,
                          height: 62,
                          child: ElevatedButton(
                            onPressed: isLoading ? null : login,
                            style: ElevatedButton.styleFrom(
                              backgroundColor: const Color(0xFF4259A9),
                              foregroundColor: Colors.white,
                              elevation: 4,
                              shadowColor: Colors.black.withOpacity(0.18),
                              shape: RoundedRectangleBorder(
                                borderRadius: BorderRadius.circular(32),
                              ),
                            ),
                            child: isLoading
                                ? const SizedBox(
                                    height: 28,
                                    width: 28,
                                    child: CircularProgressIndicator(
                                      color: Colors.white,
                                      strokeWidth: 3,
                                    ),
                                  )
                                : const Text(
                                    "Login",
                                    style: TextStyle(
                                      fontSize: 20,
                                      fontWeight: FontWeight.w600,
                                    ),
                                  ),
                          ),
                        ),

                        if (errorMessage.isNotEmpty) ...[
                          const SizedBox(height: 14),
                          Text(
                            errorMessage,
                            textAlign: TextAlign.center,
                            style: const TextStyle(
                              color: Colors.red,
                              fontWeight: FontWeight.w700,
                            ),
                          ),
                        ],

                        const SizedBox(height: 22),

                        Row(
                          mainAxisAlignment: MainAxisAlignment.center,
                          children: [
                            const Text(
                              "Don't have an account? ",
                              style: TextStyle(
                                color: Color(0xFF6F748A),
                                fontSize: 16,
                                fontWeight: FontWeight.w500,
                              ),
                            ),
                            TextButton(
                              onPressed: () {
                                Navigator.push(
                                  context,
                                  MaterialPageRoute(
                                    builder: (_) => SignupPage(),
                                  ),
                                );
                              },
                              style: TextButton.styleFrom(
                                padding: EdgeInsets.zero,
                                minimumSize: const Size(0, 0),
                                tapTargetSize: MaterialTapTargetSize.shrinkWrap,
                              ),
                              child: const Text(
                                "Sign up",
                                style: TextStyle(
                                  color: Color(0xFF4259A9),
                                  fontSize: 16,
                                  fontWeight: FontWeight.w700,
                                ),
                              ),
                            ),
                          ],
                        ),
                      ],
                    ),
                  ),
                ),
              ),
            ),
          ),
        ],
      ),
    );
  }
}

class SignupPage extends StatefulWidget {
  SignupPage({super.key});

  @override
  State<SignupPage> createState() => SignupPageState();
}

class SignupPageState extends State<SignupPage> {
  final formKey = GlobalKey<FormState>();
  final e = TextEditingController();
  final p = TextEditingController();
  final cp = TextEditingController();
  final otp = TextEditingController();

  String? selectedDept;
  List<String> departments = [];

  bool isLoading = false;
  bool isSendingOtp = false;
  bool isVerifyingOtp = false;
  bool isLoadingDepartments = true;
  bool otpVerified = false;
  String verifiedEmail = '';
  String signupOtpToken = '';
  String statusMessage = '';
  bool hasError = false;

  @override
  void initState() {
    super.initState();
    e.addListener(_handleEmailChanged);
    fetchDepartments();
  }

  void _handleEmailChanged() {
    final currentEmail = e.text.trim().toLowerCase();
    if ((otpVerified || signupOtpToken.isNotEmpty) &&
        currentEmail != verifiedEmail) {
      if (!mounted) return;
      setState(() {
        otpVerified = false;
        signupOtpToken = '';
        verifiedEmail = '';
      });
    }
  }

  @override
  void dispose() {
    e.removeListener(_handleEmailChanged);
    e.dispose();
    p.dispose();
    cp.dispose();
    otp.dispose();
    super.dispose();
  }

  Future<Map<String, dynamic>> _decodeResponse(http.Response response) async {
    try {
      final decoded = jsonDecode(response.body);
      if (decoded is Map<String, dynamic>) {
        return decoded;
      }
    } catch (_) {}
    return {};
  }

  void _setStatus(String message, {bool isError = false}) {
    if (!mounted) return;
    setState(() {
      statusMessage = message;
      hasError = isError;
    });
  }

  Future<void> fetchDepartments() async {
    final baseUrl = getBaseUrl();
    final url = Uri.parse("$baseUrl/api/mobile/departments");

    try {
      final response = await http.get(url).timeout(const Duration(seconds: 10));
      final data = await _decodeResponse(response);
      final rawDepartments = data['departments'];
      final fetched = <String>[];

      if (rawDepartments is List) {
        for (final item in rawDepartments) {
          final value = item.toString().trim();
          if (value.isNotEmpty) fetched.add(value);
        }
      }

      if (!mounted) return;
      setState(() {
        departments = fetched;
      });
    } catch (_) {
      _setStatus('Unable to load departments. Please try again.', isError: true);
    } finally {
      if (mounted) {
        setState(() => isLoadingDepartments = false);
      }
    }
  }

  Future<void> sendOtp() async {
    final email = e.text.trim().toLowerCase();
    if (email.isEmpty) {
      _setStatus('Enter your email first.', isError: true);
      return;
    }

    final baseUrl = getBaseUrl();
    final url = Uri.parse("$baseUrl/api/mobile/send-otp");

    setState(() {
      isSendingOtp = true;
      otpVerified = false;
      signupOtpToken = '';
      verifiedEmail = '';
      statusMessage = '';
    });

    try {
      final response = await http
          .post(
            url,
            headers: {"Content-Type": "application/json"},
            body: jsonEncode({"email": email}),
          )
          .timeout(const Duration(seconds: 15));

      final data = await _decodeResponse(response);

      if (response.statusCode == 200) {
        if (!mounted) return;
        setState(() {
          otpVerified = false;
          signupOtpToken = '';
          verifiedEmail = '';
        });
        _setStatus(data['message'] ?? 'OTP sent successfully.');
      } else {
        _setStatus(data['error'] ?? 'Failed to send OTP.', isError: true);
      }
    } catch (err) {
      _setStatus('Cannot connect to server: $err', isError: true);
    } finally {
      if (mounted) {
        setState(() => isSendingOtp = false);
      }
    }
  }

  Future<void> verifyOtp() async {
    final email = e.text.trim().toLowerCase();
    final otpCode = otp.text.trim();

    if (email.isEmpty) {
      _setStatus('Enter your email first.', isError: true);
      return;
    }
    if (otpCode.length != 6) {
      _setStatus('Enter a valid 6-digit OTP.', isError: true);
      return;
    }

    final baseUrl = getBaseUrl();
    final url = Uri.parse("$baseUrl/api/mobile/verify-otp");

    setState(() {
      isVerifyingOtp = true;
      statusMessage = '';
    });

    try {
      final response = await http
          .post(
            url,
            headers: {"Content-Type": "application/json"},
            body: jsonEncode({"email": email, "otp": otpCode}),
          )
          .timeout(const Duration(seconds: 15));

      final data = await _decodeResponse(response);

      if (response.statusCode == 200) {
        final token = (data['signup_otp_token'] ?? '').toString();
        if (token.isEmpty) {
          _setStatus('Verification token missing. Please try again.',
              isError: true);
          return;
        }

        if (!mounted) return;
        setState(() {
          otpVerified = true;
          signupOtpToken = token;
          verifiedEmail = email;
        });
        _setStatus(data['message'] ?? 'OTP verified successfully.');
      } else {
        if (!mounted) return;
        setState(() {
          otpVerified = false;
          signupOtpToken = '';
          verifiedEmail = '';
        });
        _setStatus(data['error'] ?? 'OTP verification failed.', isError: true);
      }
    } catch (err) {
      _setStatus('Cannot connect to server: $err', isError: true);
    } finally {
      if (mounted) {
        setState(() => isVerifyingOtp = false);
      }
    }
  }

  Future<void> signup() async {
    if (!formKey.currentState!.validate()) return;
    final email = e.text.trim().toLowerCase();

    if (!otpVerified || signupOtpToken.isEmpty || verifiedEmail != email) {
      _setStatus('Please verify OTP first.', isError: true);
      return;
    }

    setState(() => isLoading = true);

    final baseUrl = getBaseUrl();
    final url = Uri.parse("$baseUrl/api/mobile/signup");

    try {
      final response = await http
          .post(
            url,
            headers: {"Content-Type": "application/json"},
            body: jsonEncode({
              "email": email,
              "password": p.text,
              "confirmpassword": cp.text,
              "department": selectedDept,
              "signup_otp_token": signupOtpToken,
            }),
          )
          .timeout(const Duration(seconds: 15));

      final data = await _decodeResponse(response);

      if (response.statusCode == 201) {
        if (!mounted) return;
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text(data['message'] ?? 'Account created! Please login.'),
          ),
        );
        Navigator.pop(context);
      } else {
        _setStatus(data['error'] ?? 'Signup failed.', isError: true);
      }
    } catch (err) {
      _setStatus('Cannot connect to server: $err', isError: true);
    } finally {
      if (mounted) {
        setState(() => isLoading = false);
      }
    }
  }

  InputDecoration _signupInputDecoration({
    required String hint,
    required IconData icon,
  }) {
    return InputDecoration(
      hintText: hint,
      hintStyle: const TextStyle(
        color: Color(0xFF6A6F87),
        fontSize: 16,
        fontWeight: FontWeight.w500,
      ),
      prefixIcon: Icon(
        icon,
        color: const Color(0xFF6A6F87),
      ),
      filled: true,
      fillColor: Colors.white.withOpacity(0.95),
      contentPadding: const EdgeInsets.symmetric(horizontal: 18, vertical: 18),
      border: OutlineInputBorder(
        borderRadius: BorderRadius.circular(18),
        borderSide: BorderSide.none,
      ),
      enabledBorder: OutlineInputBorder(
        borderRadius: BorderRadius.circular(18),
        borderSide: BorderSide.none,
      ),
      focusedBorder: OutlineInputBorder(
        borderRadius: BorderRadius.circular(18),
        borderSide: const BorderSide(
          color: Color(0xFF3E56A6),
          width: 1.2,
        ),
      ),
      errorBorder: OutlineInputBorder(
        borderRadius: BorderRadius.circular(18),
        borderSide: const BorderSide(color: Colors.red),
      ),
      focusedErrorBorder: OutlineInputBorder(
        borderRadius: BorderRadius.circular(18),
        borderSide: const BorderSide(color: Colors.red),
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      resizeToAvoidBottomInset: true,
      body: Stack(
        children: [
          Positioned.fill(
            child: Image.asset(
              'assets/img3.png',
              fit: BoxFit.cover,
            ),
          ),
          SafeArea(
            child: Column(
              children: [
                Align(
                  alignment: Alignment.centerLeft,
                  child: IconButton(
                    icon: const Icon(
                      Icons.arrow_back,
                      color: Color(0xFF1F2A5A),
                    ),
                    onPressed: () => Navigator.pop(context),
                  ),
                ),
                Expanded(
                  child: Center(
                    child: SingleChildScrollView(
                      padding: const EdgeInsets.symmetric(
                        horizontal: 24,
                        vertical: 12,
                      ),
                      child: ConstrainedBox(
                        constraints: const BoxConstraints(maxWidth: 430),
                        child: Form(
                          key: formKey,
                          child: Container(
                            padding: const EdgeInsets.all(22),
                            decoration: BoxDecoration(
                              color: Colors.white.withOpacity(0.18),
                              borderRadius: BorderRadius.circular(28),
                            ),
                            child: Column(
                              crossAxisAlignment: CrossAxisAlignment.stretch,
                              children: [
                                const Text(
                                  "Create Account",
                                  textAlign: TextAlign.center,
                                  style: TextStyle(
                                    fontSize: 30,
                                    fontWeight: FontWeight.w800,
                                    color: Color(0xFF2B3771),
                                  ),
                                ),
                                const SizedBox(height: 8),
                                const Text(
                                  "Join the company workspace",
                                  textAlign: TextAlign.center,
                                  style: TextStyle(
                                    color: Color(0xFF6F748A),
                                    fontSize: 15,
                                    fontWeight: FontWeight.w500,
                                  ),
                                ),
                                const SizedBox(height: 18),

                                if (isLoadingDepartments)
                                  const Padding(
                                    padding: EdgeInsets.only(bottom: 14),
                                    child: LinearProgressIndicator(),
                                  ),

                                TextFormField(
                                  controller: e,
                                  decoration: _signupInputDecoration(
                                    hint: "Email Address",
                                    icon: Icons.email_outlined,
                                  ),
                                  validator: (v) {
                                    if (v == null || v.isEmpty) {
                                      return "Email required";
                                    }
                                    if (!v.contains('@')) return 'Invalid email';
                                    return null;
                                  },
                                ),
                                const SizedBox(height: 14),

                                DropdownButtonFormField<String>(
                                  value: selectedDept,
                                  decoration: _signupInputDecoration(
                                    hint: "Department",
                                    icon: Icons.business_outlined,
                                  ),
                                  items: departments
                                      .map(
                                        (d) => DropdownMenuItem(
                                          value: d,
                                          child: Text(d),
                                        ),
                                      )
                                      .toList(),
                                  onChanged: (val) =>
                                      setState(() => selectedDept = val),
                                  validator: (v) =>
                                      v == null ? 'Select a department' : null,
                                ),
                                const SizedBox(height: 14),

                                TextFormField(
                                  controller: otp,
                                  enabled: !otpVerified,
                                  keyboardType: TextInputType.number,
                                  maxLength: 6,
                                  decoration: _signupInputDecoration(
                                    hint: "OTP",
                                    icon: Icons.verified_user_outlined,
                                  ),
                                  validator: (v) {
                                    if (v == null || v.trim().isEmpty) {
                                      return 'OTP required';
                                    }
                                    if (v.trim().length != 6) {
                                      return 'OTP must be 6 digits';
                                    }
                                    return null;
                                  },
                                ),
                                const SizedBox(height: 8),

                                LayoutBuilder(
                                  builder: (context, constraints) {
                                    final isNarrow = constraints.maxWidth < 360;

                                    final sendButton = OutlinedButton.icon(
                                      onPressed: (isSendingOtp ||
                                              isVerifyingOtp ||
                                              isLoading)
                                          ? null
                                          : sendOtp,
                                      style: OutlinedButton.styleFrom(
                                        backgroundColor: Colors.white,
                                        foregroundColor: const Color(0xFF3E56A6),
                                        side: const BorderSide(
                                          color: Color(0xFF3E56A6),
                                        ),
                                        shape: RoundedRectangleBorder(
                                          borderRadius:
                                              BorderRadius.circular(16),
                                        ),
                                        padding: const EdgeInsets.symmetric(
                                          vertical: 14,
                                        ),
                                      ),
                                      icon: isSendingOtp
                                          ? const SizedBox(
                                              height: 16,
                                              width: 16,
                                              child: CircularProgressIndicator(
                                                strokeWidth: 2,
                                              ),
                                            )
                                          : const Icon(Icons.mail_outline),
                                      label: Text(
                                        isSendingOtp
                                            ? 'Sending...'
                                            : 'Send OTP',
                                      ),
                                    );

                                    final verifyButton = OutlinedButton.icon(
                                      onPressed: (isVerifyingOtp ||
                                              otpVerified ||
                                              isLoading)
                                          ? null
                                          : verifyOtp,
                                      style: OutlinedButton.styleFrom(
                                        backgroundColor: Colors.white,
                                        foregroundColor: const Color(0xFF3E56A6),
                                        side: const BorderSide(
                                          color: Color(0xFF3E56A6),
                                        ),
                                        shape: RoundedRectangleBorder(
                                          borderRadius:
                                              BorderRadius.circular(16),
                                        ),
                                        padding: const EdgeInsets.symmetric(
                                          vertical: 14,
                                        ),
                                      ),
                                      icon: isVerifyingOtp
                                          ? const SizedBox(
                                              height: 16,
                                              width: 16,
                                              child: CircularProgressIndicator(
                                                strokeWidth: 2,
                                              ),
                                            )
                                          : Icon(
                                              otpVerified
                                                  ? Icons.verified
                                                  : Icons.shield_outlined,
                                            ),
                                      label: Text(
                                        isVerifyingOtp
                                            ? 'Verifying...'
                                            : (otpVerified
                                                ? 'OTP Verified'
                                                : 'Verify OTP'),
                                      ),
                                    );

                                    if (isNarrow) {
                                      return Column(
                                        crossAxisAlignment:
                                            CrossAxisAlignment.stretch,
                                        children: [
                                          sendButton,
                                          const SizedBox(height: 8),
                                          verifyButton,
                                        ],
                                      );
                                    }

                                    return Row(
                                      children: [
                                        Expanded(child: sendButton),
                                        const SizedBox(width: 8),
                                        Expanded(child: verifyButton),
                                      ],
                                    );
                                  },
                                ),
                                const SizedBox(height: 14),

                                TextFormField(
                                  controller: p,
                                  obscureText: true,
                                  decoration: _signupInputDecoration(
                                    hint: "Password",
                                    icon: Icons.lock_outlined,
                                  ),
                                  validator: (v) {
                                    if (v == null || v.isEmpty) {
                                      return "Password required";
                                    }
                                    if (v.length < 6) {
                                      return 'Min 6 characters';
                                    }
                                    if (!RegExp(r'[A-Z]').hasMatch(v)) {
                                      return 'Must include uppercase letter';
                                    }
                                    if (!RegExp(r'\d').hasMatch(v)) {
                                      return 'Must include a number';
                                    }
                                    return null;
                                  },
                                ),
                                const SizedBox(height: 14),

                                TextFormField(
                                  controller: cp,
                                  obscureText: true,
                                  decoration: _signupInputDecoration(
                                    hint: "Confirm Password",
                                    icon: Icons.lock_outline,
                                  ),
                                  validator: (v) {
                                    if (v == null || v.isEmpty) {
                                      return "Confirm password";
                                    }
                                    if (v != p.text) {
                                      return 'Passwords do not match';
                                    }
                                    return null;
                                  },
                                ),
                                const SizedBox(height: 22),

                                SizedBox(
                                  height: 56,
                                  child: ElevatedButton(
                                    onPressed: isLoading ? null : signup,
                                    style: ElevatedButton.styleFrom(
                                      backgroundColor: const Color(0xFF4259A9),
                                      foregroundColor: Colors.white,
                                      shape: RoundedRectangleBorder(
                                        borderRadius: BorderRadius.circular(28),
                                      ),
                                    ),
                                    child: isLoading
                                        ? const SizedBox(
                                            height: 24,
                                            width: 24,
                                            child: CircularProgressIndicator(
                                              color: Colors.white,
                                              strokeWidth: 3,
                                            ),
                                          )
                                        : const Text(
                                            "Sign Up",
                                            style: TextStyle(
                                              fontSize: 18,
                                              fontWeight: FontWeight.w700,
                                            ),
                                          ),
                                  ),
                                ),

                                if (statusMessage.isNotEmpty) ...[
                                  const SizedBox(height: 12),
                                  Text(
                                    statusMessage,
                                    textAlign: TextAlign.center,
                                    style: TextStyle(
                                      color: hasError
                                          ? Colors.red
                                          : Colors.green,
                                      fontWeight: FontWeight.w700,
                                    ),
                                  ),
                                ],
                              ],
                            ),
                          ),
                        ),
                      ),
                    ),
                  ),
                ),
              ],
            ),
          ),
        ],
      ),
    );
  }
}