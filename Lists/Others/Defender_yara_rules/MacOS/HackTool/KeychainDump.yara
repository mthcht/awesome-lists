rule HackTool_MacOS_KeychainDump_A_2147750193_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:MacOS/KeychainDump.A!MTB"
        threat_id = "2147750193"
        type = "HackTool"
        platform = "MacOS: "
        family = "KeychainDump"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "[-] Could not allocate memory for key search" ascii //weight: 1
        $x_1_2 = "[-] The target file is not a keychain file" ascii //weight: 1
        $x_1_3 = "[*] Trying to decrypt wrapping key in %s" ascii //weight: 1
        $x_1_4 = "_find_or_create_credentials" ascii //weight: 1
        $x_1_5 = "%s/Library/Keychains/login.keychain" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule HackTool_MacOS_KeychainDump_C_2147838126_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:MacOS/KeychainDump.C!MTB"
        threat_id = "2147838126"
        type = "HackTool"
        platform = "MacOS: "
        family = "KeychainDump"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "keychain_dumper" ascii //weight: 1
        $x_1_2 = "/var/Keychains/keychain-2.db" ascii //weight: 1
        $x_1_3 = "dumpKeychainEntitlements" ascii //weight: 1
        $x_1_4 = "Dump Internet Passwords" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

