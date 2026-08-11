rule Ransom_Win64_Aurora_SK_2147975981_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Aurora.SK!MTB"
        threat_id = "2147975981"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Aurora"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "We have downloaded confidential information files. Your files are encrypted" ascii //weight: 1
        $x_1_2 = "WARNING: RNG returned all zeros, encryption keys may be weak" ascii //weight: 1
        $x_1_3 = "vssadmin resize shadowstorage /for=%c: /on=%c: /maxsize=401MB >nul 2>" ascii //weight: 1
        $x_1_4 = "schtasks /Change /TN \"\\Microsoft\\Windows\\SystemRestore\\SR\" /Disable >nul 2>" ascii //weight: 1
        $x_1_5 = "!!!README!!!DO_NOT_DELETE.txt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

