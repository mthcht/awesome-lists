rule Trojan_Win32_Anomaly_2147584357_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Anomaly"
        threat_id = "2147584357"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Anomaly"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 46 52 5f 53 74 65 61 6c 65 72 5f ?? ?? (30|31|32|33|34|35|36|37|38|39) (30|31|32|33|34|35|36|37|38|39)}  //weight: 1, accuracy: Low
        $x_1_2 = ".purple\\accounts.xml" ascii //weight: 1
        $x_1_3 = {5c 54 68 65 20 42 61 74 21 5c 00 25 73 25 73 5c 41 63 63 6f 75 6e 74 2e 63 66 6e}  //weight: 1, accuracy: High
        $x_1_4 = "SELECT hostname, encryptedUsername, encryptedPassword FROM moz_logins" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

