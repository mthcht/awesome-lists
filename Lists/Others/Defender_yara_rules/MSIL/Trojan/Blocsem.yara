rule Trojan_MSIL_Blocsem_A_2147706781_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Blocsem.A"
        threat_id = "2147706781"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Blocsem"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/ufaktrack.php" wide //weight: 1
        $x_1_2 = "/atak.php" wide //weight: 1
        $x_1_3 = "n|reg add HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run /v \"macrosoft\" /d %APPDATA%\\Flash.exe" wide //weight: 1
        $x_1_4 = "n|reg add HKLM\\SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Run /v \"macrosoft\" /d %APPDATA%\\Flash.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

