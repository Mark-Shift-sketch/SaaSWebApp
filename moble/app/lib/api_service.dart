import 'dart:convert';
import 'package:http/http.dart' as http;
import 'package:shared_preferences/shared_preferences.dart';
import 'package:flutter/foundation.dart' show kIsWeb;
import 'dart:io' show Platform;

// same base url helper
String getBaseUrl() {
  if (kIsWeb) {
    final host = Uri.base.host;
    return "http://$host:5000";
  }
  if (Platform.isAndroid) return "http://10.0.2.2:5000";
  if (Platform.isWindows) return "http://127.0.0.1:5000";
  return "http://192.168.0.102:5000";
}

class ApiService {
  static Future<String?> _getToken() async {
    final prefs = await SharedPreferences.getInstance();
    return prefs.getString("token");
  }

  // Startup auth check
  static Future<Map<String, dynamic>> fetchMobileUserProfile() async {
    final baseUrl = getBaseUrl();
    final url = Uri.parse("$baseUrl/api/mobile/user-profile");

    final res = await http.get(url, headers: await _headers());
    if (res.statusCode != 200) {
      throw Exception("Profile failed: ${res.statusCode} ${res.body}");
    }

    final decoded = jsonDecode(res.body);
    if (decoded is Map<String, dynamic>) {
      if (decoded["error"] != null) {
        throw Exception(decoded["error"].toString());
      }
      return decoded;
    }
    throw Exception("Invalid profile response");
  }

  static Future<Map<String, String>> _headers() async {
    final token = await _getToken();
    final headers = <String, String>{"Content-Type": "application/json"};
    if (token != null && token.isNotEmpty) {
      headers["Authorization"] = "Bearer $token";
    }
    return headers;
  }

  // Notifications
  static Future<List<dynamic>> fetchUserNotifications() async {
    final baseUrl = getBaseUrl();
    final url = Uri.parse("$baseUrl/api/mobile/notifications");

    final res = await http.get(url, headers: await _headers());
    if (res.statusCode != 200) {
      throw Exception("Notifications failed: ${res.statusCode} ${res.body}");
    }

    final decoded = jsonDecode(res.body);
    if (decoded is List) return decoded;
    return [];
  }

  // Activity Logs
  static Future<List<dynamic>> fetchActivityLogs() async {
    final baseUrl = getBaseUrl();
    final url = Uri.parse("$baseUrl/api/activity_logs");

    final res = await http.get(url, headers: await _headers());
    if (res.statusCode != 200) {
      throw Exception("Activity logs failed: ${res.statusCode} ${res.body}");
    }

    final decoded = jsonDecode(res.body);
    if (decoded is Map &&
        decoded["success"] == true &&
        decoded["data"] is List) {
      return decoded["data"] as List;
    }
    return [];
  }

  // Dashboard
  static Future<Map<String, dynamic>> fetchUserDashboard() async {
    final baseUrl = getBaseUrl();
    final url = Uri.parse("$baseUrl/api/user_dashboard");

    final res = await http.get(url, headers: await _headers());
    if (res.statusCode != 200) {
      throw Exception("Dashboard failed: ${res.statusCode} ${res.body}");
    }

    final decoded = jsonDecode(res.body);
    if (decoded is Map<String, dynamic>) return decoded;
    return {};
  }
}
