rule Trojan_Win32_CryptoJacker_A_2147726232_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptoJacker.A"
        threat_id = "2147726232"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptoJacker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {83 f8 0d 75 23 8b 45 fc 66 83 38 52 75 1a 8d 45 d4 8b 55 f8}  //weight: 10, accuracy: High
        $x_10_2 = {83 f8 0d 75 23 8b 45 fc 66 83 38 5a 75 1a 8d 45 d0 8b 55 f4}  //weight: 10, accuracy: High
        $x_10_3 = {83 f8 2a 75 23 8b 45 fc 66 83 38 30 75 1a 8d 45 bc 8b 55 e4}  //weight: 10, accuracy: High
        $x_10_4 = {83 f8 22 75 23 8b 45 fc 66 83 38 31 75 1a 8d 45 c0 8b 55 e8}  //weight: 10, accuracy: High
        $x_10_5 = {83 f8 6a 75 23 8b 45 fc 66 83 38 34 75 1a 8d 45 b8 8b 55 e0}  //weight: 10, accuracy: High
        $x_10_6 = {83 f8 22 75 23 8b 45 fc 66 83 38 4c 75 1a 8d 45 b4 8b 55 d8}  //weight: 10, accuracy: High
        $x_10_7 = "cmd /k attrib +s +h \"C:\\ProgramData\\NVIDIA\\NVDisplay.Container.exe\"" ascii //weight: 10
        $x_10_8 = "C:\\ProgramData\\NVIDIA\\NVDisplay.Container.exe" ascii //weight: 10
        $x_10_9 = "0xE44598AB74425450692F7b3a9f898119968da8Ad" ascii //weight: 10
        $x_10_10 = "4BrL51JCc9NGQ71kWhnYoDRffsDZy7m1HUU7MRU4nUMXAHNFBE" ascii //weight: 10
        $x_10_11 = "1LGskAycxvcgh6iAoigcvbwTtFjSfdod2x" ascii //weight: 10
        $x_10_12 = "LYB56d6TeMg6VmahcgfTZSALAQRcNRQUVd" ascii //weight: 10
        $x_10_13 = "79965017478" ascii //weight: 10
        $x_10_14 = "R064565691369" ascii //weight: 10
        $x_10_15 = "Z152913748562" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

