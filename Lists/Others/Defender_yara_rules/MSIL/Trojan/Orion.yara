rule Trojan_MSIL_Orion_AOR_2147841223_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Orion.AOR!MTB"
        threat_id = "2147841223"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Orion"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "oriongrabber.xyz" wide //weight: 1
        $x_1_2 = "Orion Free v1.3.exe" wide //weight: 1
        $x_1_3 = "Marks the process as critical, making it impossible to kill using task manager" wide //weight: 1
        $x_1_4 = "Spreads the stealer along with the message to all friends on discord" wide //weight: 1
        $x_1_5 = "Exits when it detects being in a malware analysis VM" wide //weight: 1
        $x_1_6 = "Prevents the same token from being logged" wide //weight: 1
        $x_1_7 = "Sends you the new token and password after victim changes their password" wide //weight: 1
        $x_1_8 = "Takes saved passwords from their browsers" wide //weight: 1
        $x_1_9 = "Takes saved wifi passwords" wide //weight: 1
        $x_1_10 = "Takes saved roblox cookies" wide //weight: 1
        $x_1_11 = "Changes the crypto address in clipboard to your own" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

