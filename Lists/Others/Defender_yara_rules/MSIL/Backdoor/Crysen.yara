rule Backdoor_MSIL_Crysen_S_2147754512_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Crysen.S!MTB"
        threat_id = "2147754512"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Crysen"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/c schtasks /create /f /sc onlogon /ru system /rl highest /tn" ascii //weight: 1
        $x_1_2 = "\\nuR\\noisreVtnerruC\\swodniW\\tfosorciM\\erawtfoS" ascii //weight: 1
        $x_1_3 = "Pastebin" ascii //weight: 1
        $x_1_4 = "Select * from AntivirusProduct" ascii //weight: 1
        $x_1_5 = "masterKey can not be null or empty." ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Crysen_AD_2147755022_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Crysen.AD!MTB"
        threat_id = "2147755022"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Crysen"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "X509Certificate" ascii //weight: 1
        $x_1_2 = "ValidateServerCertificate" ascii //weight: 1
        $x_1_3 = "set_UseShellExecute" ascii //weight: 1
        $x_1_4 = "FromBase64String" ascii //weight: 1
        $x_1_5 = "DownloadString" ascii //weight: 1
        $x_1_6 = "RemoteCertificateValidationCallback" ascii //weight: 1
        $x_1_7 = "NetworkCredential" ascii //weight: 1
        $x_1_8 = "Client.Install" ascii //weight: 1
        $x_1_9 = "MutexControl" ascii //weight: 1
        $x_1_10 = "DetectDebugger" ascii //weight: 1
        $x_1_11 = "Client.Helper" ascii //weight: 1
        $x_1_12 = "CreateEncryptor" ascii //weight: 1
        $x_1_13 = "Anti_Analysis" ascii //weight: 1
        $x_1_14 = "ICredentials" ascii //weight: 1
        $x_1_15 = "Antivirus" ascii //weight: 1
        $x_1_16 = "Client.Handle_Packet" ascii //weight: 1
        $x_1_17 = "CheckRemoteDebuggerPresent" ascii //weight: 1
        $x_1_18 = "set_CreateNoWindow" ascii //weight: 1
        $x_1_19 = "\\nuR\\noisreVtnerruC\\swodniW\\tfosorciM\\erawtfoS" wide //weight: 1
        $x_1_20 = "Select * from AntivirusProduct" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

