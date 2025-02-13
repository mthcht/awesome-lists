rule TrojanDownloader_Win32_Pokier_2147575184_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Pokier"
        threat_id = "2147575184"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Pokier"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "44"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Keep-Alive" ascii //weight: 1
        $x_1_2 = "%s: basic" ascii //weight: 1
        $x_1_3 = "Authorization" ascii //weight: 1
        $x_1_4 = "Proxy-Authorization" ascii //weight: 1
        $x_1_5 = "%s: Keep-Alive" ascii //weight: 1
        $x_1_6 = "Proxy-Connection" ascii //weight: 1
        $x_1_7 = "content-length" ascii //weight: 1
        $x_1_8 = "http://%s%s" ascii //weight: 1
        $x_1_9 = "HTTP/1.0 404 Not Found" ascii //weight: 1
        $x_1_10 = "Proxy-Connection: close" ascii //weight: 1
        $x_1_11 = "Content-type: text/html; unsigned charset=us-ascii" ascii //weight: 1
        $x_1_12 = "<html><head><title>404 Not Found</title></head>" ascii //weight: 1
        $x_1_13 = "Content-Type: text/html" ascii //weight: 1
        $x_1_14 = "HTTP/1.0 200 Connection established" ascii //weight: 1
        $x_1_15 = "HTTP/1.0 407 Proxy Authentication Required" ascii //weight: 1
        $x_1_16 = "Proxy-Authenticate: Basic realm=\"proxy\"" ascii //weight: 1
        $x_1_17 = "HTTP/1.0 500 Internal Error" ascii //weight: 1
        $x_1_18 = "HTTP/1.0 503 Service Unavailable" ascii //weight: 1
        $x_1_19 = "NON_ELITE" ascii //weight: 1
        $x_1_20 = "ELITE" ascii //weight: 1
        $x_1_21 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_22 = "%swu%s.exe" ascii //weight: 1
        $x_1_23 = "Allow all activities for this application" ascii //weight: 1
        $x_1_24 = "&Unblock" ascii //weight: 1
        $x_1_25 = "Windows Security Alert" ascii //weight: 1
        $x_1_26 = "Hidden Process Requests Network Access" ascii //weight: 1
        $x_1_27 = "Warning: Components Have Changed" ascii //weight: 1
        $x_1_28 = "Create rule for  %s" ascii //weight: 1
        $x_1_29 = "%s?ip=%s&p1=%u&p2=%u&ID=%s&ver=%s&net=%s&speed=%d.1&os=%s&type=%s" ascii //weight: 1
        $x_1_30 = "%temp%\\" ascii //weight: 1
        $x_1_31 = "Mozilla/5.0" ascii //weight: 1
        $x_1_32 = "Microsoft_Win32s_" ascii //weight: 1
        $x_1_33 = "Microsoft_Windows_Millennium_Edition_" ascii //weight: 1
        $x_1_34 = "Microsoft_Windows_98_" ascii //weight: 1
        $x_1_35 = "Microsoft_Windows_95_" ascii //weight: 1
        $x_1_36 = "Service_Pack_6" ascii //weight: 1
        $x_1_37 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Hotfix" ascii //weight: 1
        $x_1_38 = "SERVERNT" ascii //weight: 1
        $x_1_39 = "LANMANNT" ascii //weight: 1
        $x_1_40 = "Workstation_" ascii //weight: 1
        $x_1_41 = "ProductType" ascii //weight: 1
        $x_1_42 = "SYSTEM\\CurrentControlSet\\Control\\ProductOptions" ascii //weight: 1
        $x_1_43 = "Server_4.0_" ascii //weight: 1
        $x_1_44 = "Advanced_Server_" ascii //weight: 1
        $x_1_45 = "Datacenter_Server_" ascii //weight: 1
        $x_1_46 = "Standard_Edition_" ascii //weight: 1
        $x_1_47 = "Web_Edition_" ascii //weight: 1
        $x_1_48 = "Professional_" ascii //weight: 1
        $x_1_49 = "Home_Edition_" ascii //weight: 1
        $x_1_50 = "Microsoft_Windows_NT_" ascii //weight: 1
        $x_1_51 = "Microsoft_Windows_2000_" ascii //weight: 1
        $x_1_52 = "Microsoft_Windows_XP_" ascii //weight: 1
        $x_1_53 = "Microsoft_Windows.NET(Server2003 family)_" ascii //weight: 1
        $x_1_54 = "SeDebugPrivilege" ascii //weight: 1
        $x_1_55 = "\\Microsoft\\" ascii //weight: 1
        $x_1_56 = "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders" ascii //weight: 1
        $x_1_57 = "AppData" ascii //weight: 1
        $x_1_58 = "%sxtempx.xxx" ascii //weight: 1
        $x_1_59 = "\\Releases\\" ascii //weight: 1
        $x_1_60 = "socks_web_report\\" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (44 of ($x*))
}

