import 'package:flutter/material.dart';
import 'dart:convert';
import 'package:http/http.dart' as http;
import 'homepage.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'package:flutter/foundation.dart' show kIsWeb;
import 'dart:io' show Platform;

class LoginPage extends StatefulWidget {
  const LoginPage({super.key});

  @override
  State<LoginPage> createState() => LoginPageState();
}

String getBaseUrl() {
  // Flutter Web (Edge/Chrome)
  if (kIsWeb) {
    final host = Uri.base.host; 
    return "http://$host:5000";
  }

  // Windows desktop app 
  if (Platform.isWindows) return "http://127.0.0.1:5000";


  // Real phone / other device on same Wi-Fi (change to YOUR PC IP)
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

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: Colors.white,
      body: Center(
        child: SingleChildScrollView(
          padding: const EdgeInsets.all(24.0),
          child: ConstrainedBox(
            constraints: const BoxConstraints(maxWidth: 400),
            child: Form(
              key: formKey,
              child: Column(
                mainAxisAlignment: MainAxisAlignment.center,
                crossAxisAlignment: CrossAxisAlignment.stretch,
                children: [
                  const Icon(Icons.account_circle,
                      size: 80, color: Colors.greenAccent),
                  const SizedBox(height: 24),
                  Text(
                    "Welcome Back",
                    textAlign: TextAlign.center,
                    style: Theme.of(context).textTheme.headlineMedium?.copyWith(
                          fontWeight: FontWeight.bold,
                          color: Colors.black87,
                        ),
                  ),
                  const SizedBox(height: 8),
                  Text(
                    'Sign in to continue',
                    textAlign: TextAlign.center,
                    style: TextStyle(color: Colors.grey.shade600),
                  ),
                  const SizedBox(height: 32),
                  TextFormField(
                    controller: e,
                    decoration: const InputDecoration(
                      labelText: "Email Address",
                      prefixIcon: Icon(Icons.email_outlined),
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
                  const SizedBox(height: 16),
                  TextFormField(
                    controller: p,
                    obscureText: true,
                    decoration: const InputDecoration(
                      labelText: 'Password',
                      prefixIcon: Icon(Icons.lock_outlined),
                    ),
                    validator: (value) {
                      if (value == null || value.isEmpty) {
                        return 'Please enter your password';
                      }
                      return null;
                    },
                  ),
                  const SizedBox(height: 24),
                  SizedBox(
                    height: 50,
                    child: FilledButton(
                      onPressed: isLoading ? null : login,
                      child: isLoading
                          ? const CircularProgressIndicator(color: Colors.white)
                          : const Text("Login",
                              style: TextStyle(fontSize: 16)),
                    ),
                  ),
                  if (errorMessage.isNotEmpty) ...[
                    const SizedBox(height: 12),
                    Text(
                      errorMessage,
                      style: const TextStyle(
                          color: Colors.red, fontWeight: FontWeight.w600),
                      textAlign: TextAlign.center,
                    ),
                  ],
                  const SizedBox(height: 16),
                  Row(
                    mainAxisAlignment: MainAxisAlignment.center,
                    children: [
                      Text(
                        "Don't have an account?",
                        style: TextStyle(color: Colors.grey.shade600),
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
                        child: const Text("Sign up"),
                      ),
                    ],
                  ),
                ],
              ),
            ),
          ),
        ),
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
    if ((otpVerified || signupOtpToken.isNotEmpty) && currentEmail != verifiedEmail) {
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
          _setStatus('Verification token missing. Please try again.', isError: true);
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

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        backgroundColor: Colors.transparent,
        elevation: 0,
        leading: IconButton(
          icon: const Icon(Icons.arrow_back, color: Colors.black),
          onPressed: () => Navigator.pop(context),
        ),
      ),
      backgroundColor: Colors.white,
      body: Center(
        child: SingleChildScrollView(
          padding: const EdgeInsets.all(24.0),
          child: ConstrainedBox(
            constraints: const BoxConstraints(maxWidth: 400),
            child: Form(
              key: formKey,
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.stretch,
                children: [
                  Text(
                    "Create Account",
                    style: Theme.of(context).textTheme.headlineMedium?.copyWith(
                          fontWeight: FontWeight.bold,
                          color: Colors.black87,
                        ),
                  ),
                  const SizedBox(height: 8),
                  Text(
                    "Join the company workspace",
                    style: TextStyle(color: Colors.grey.shade600),
                  ),
                  const SizedBox(height: 16),
                  if (isLoadingDepartments)
                    const Padding(
                      padding: EdgeInsets.only(bottom: 16),
                      child: LinearProgressIndicator(),
                    ),
                  TextFormField(
                    controller: e,
                    decoration: const InputDecoration(
                      labelText: "Email Address",
                      prefixIcon: Icon(Icons.email_outlined),
                    ),
                    validator: (v) {
                      if (v == null || v.isEmpty) return "Email required";
                      if (!v.contains('@')) return 'Invalid email';
                      return null;
                    },
                  ),
                  const SizedBox(height: 16),
                  DropdownButtonFormField<String>(
                    value: selectedDept,
                    decoration: const InputDecoration(
                      labelText: "Department",
                      prefixIcon: Icon(Icons.business_outlined),
                    ),
                    items: departments
                        .map((d) => DropdownMenuItem(value: d, child: Text(d)))
                        .toList(),
                    onChanged: (val) => setState(() => selectedDept = val),
                    validator: (v) => v == null ? 'Select a department' : null,
                  ),
                  const SizedBox(height: 16),
                  TextFormField(
                    controller: otp,
                    enabled: !otpVerified,
                    keyboardType: TextInputType.number,
                    decoration: const InputDecoration(
                      labelText: "OTP",
                      prefixIcon: Icon(Icons.verified_user_outlined),
                    ),
                    maxLength: 6,
                    validator: (v) {
                      if (v == null || v.trim().isEmpty) return 'OTP required';
                      if (v.trim().length != 6) return 'OTP must be 6 digits';
                      return null;
                    },
                  ),
                  const SizedBox(height: 6),
                  LayoutBuilder(
                    builder: (context, constraints) {
                      final isNarrow = constraints.maxWidth < 360;

                      final sendButton = OutlinedButton.icon(
                        onPressed: (isSendingOtp || isVerifyingOtp || isLoading)
                            ? null
                            : sendOtp,
                        icon: isSendingOtp
                            ? const SizedBox(
                                height: 16,
                                width: 16,
                                child: CircularProgressIndicator(strokeWidth: 2),
                              )
                            : const Icon(Icons.mail_outline),
                        label: Text(isSendingOtp ? 'Sending...' : 'Send OTP'),
                      );

                      final verifyButton = OutlinedButton.icon(
                        onPressed: (isVerifyingOtp || otpVerified || isLoading)
                            ? null
                            : verifyOtp,
                        icon: isVerifyingOtp
                            ? const SizedBox(
                                height: 16,
                                width: 16,
                                child: CircularProgressIndicator(strokeWidth: 2),
                              )
                            : Icon(
                                otpVerified ? Icons.verified : Icons.shield_outlined,
                              ),
                        label: Text(
                          isVerifyingOtp
                              ? 'Verifying...'
                              : (otpVerified ? 'OTP Verified' : 'Verify OTP'),
                        ),
                      );

                      if (isNarrow) {
                        return Column(
                          crossAxisAlignment: CrossAxisAlignment.stretch,
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
                  const SizedBox(height: 16),
                  TextFormField(
                    controller: p,
                    obscureText: true,
                    decoration: const InputDecoration(
                      labelText: "Password",
                      prefixIcon: Icon(Icons.lock_outlined),
                    ),
                    validator: (v) {
                      if (v == null || v.isEmpty) return "Password required";
                      if (v.length < 6) return 'Min 6 characters';
                      if (!RegExp(r'[A-Z]').hasMatch(v)) {
                        return 'Must include uppercase letter';
                      }
                      if (!RegExp(r'\d').hasMatch(v)) {
                        return 'Must include a number';
                      }
                      return null;
                    },
                  ),
                  const SizedBox(height: 16),
                  TextFormField(
                    controller: cp,
                    obscureText: true,
                    decoration: const InputDecoration(
                      labelText: "Confirm Password",
                      prefixIcon: Icon(Icons.lock_outline),
                    ),
                    validator: (v) {
                      if (v == null || v.isEmpty) return "Confirm password";
                      if (v != p.text) return 'Passwords do not match';
                      return null;
                    },
                  ),
                  const SizedBox(height: 24),
                  SizedBox(
                    height: 50,
                    child: FilledButton(
                      onPressed: isLoading ? null : signup,
                      child: isLoading
                          ? const CircularProgressIndicator(color: Colors.white)
                          : const Text("Sign Up",
                              style: TextStyle(fontSize: 16)),
                    ),
                  ),
                  if (statusMessage.isNotEmpty) ...[
                    const SizedBox(height: 12),
                    Text(
                      statusMessage,
                      textAlign: TextAlign.center,
                      style: TextStyle(
                        color: hasError ? Colors.red : Colors.green,
                        fontWeight: FontWeight.w600,
                      ),
                    ),
                  ],
                ],
              ),
            ),
          ),
        ),
      ),
    );
  }
}