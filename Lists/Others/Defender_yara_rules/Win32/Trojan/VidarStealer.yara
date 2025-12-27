rule Trojan_Win32_VidarStealer_RS_2147773579_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VidarStealer.RS!MTB"
        threat_id = "2147773579"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VidarStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 c4 89 84 24 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 41 81 e1 ff 00 00 00 8a 91 ?? ?? ?? ?? 0f b6 c2 03 05 ?? ?? ?? ?? 53 25 ff 00 00 00 81 3d ?? ?? ?? ?? fd 01 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_VidarStealer_RF_2147779643_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VidarStealer.RF!MTB"
        threat_id = "2147779643"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VidarStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 f6 8b e9 85 ff 0f 8e ?? ?? ?? ?? 53 e8 ?? ?? ?? ?? 30 04 2e 81 ff 49 06 00 00 0f 85 ?? ?? ?? ?? 83 64 24 ?? 00 81 6c 24 ?? f4 ca bb 26 c1 e0 17 81 44 24 ?? 7e 2b 83 22 81 f3 da 61 0c 08}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_VidarStealer_RMA_2147779789_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VidarStealer.RMA!MTB"
        threat_id = "2147779789"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VidarStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "25"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "tvzxsxddaqwihopmqhtubgijrb" ascii //weight: 10
        $x_10_2 = "PYWuI5\\6DNrY\\tEqJaSk\\ON2K9ThJCLm" ascii //weight: 10
        $x_1_3 = "VirtualAlloc" ascii //weight: 1
        $x_1_4 = "VirtualProtect" ascii //weight: 1
        $x_1_5 = "GetCurrentProcess" ascii //weight: 1
        $x_1_6 = "WINMM.dll" ascii //weight: 1
        $x_1_7 = "IsDebuggerPresent" ascii //weight: 1
        $x_1_8 = "GetStartupInfoW" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_VidarStealer_XD_2147820407_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VidarStealer.XD!MTB"
        threat_id = "2147820407"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VidarStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b d0 89 7d fc 33 c0 8a 9c 02 ?? ?? ?? ?? 8b 7d fc 88 19 8a 9c 07 ?? ?? ?? ?? 8b 7d 08 88 5c 07 04 40 41 83 f8}  //weight: 10, accuracy: Low
        $x_1_2 = "mastodon.online" ascii //weight: 1
        $x_1_3 = "t.me/hyipsdigest" ascii //weight: 1
        $x_1_4 = "passwords.txt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_VidarStealer_UA_2147824208_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VidarStealer.UA!MTB"
        threat_id = "2147824208"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VidarStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b c7 0f 43 4d ?? 33 d2 f7 75 ?? 8b 45 ?? 8a 0c 0a 32 0c 38 88 4d ?? 3b 5e ?? ?? ?? 88 0b ff 46}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_VidarStealer_A_2147905378_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VidarStealer.A!MTB"
        threat_id = "2147905378"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VidarStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "LpClijtQ7JTjI76jVm9WzMItHmX76w98w0qca194rVDF6465NN9TRGCPmyFYGVPG" ascii //weight: 2
        $x_2_2 = "cnV3uYP0dMtJcR+ZQF3Hyh7cOj32BKbH2FIya1CX6jtOT2WfCnjEPqoYCGHzZimq" ascii //weight: 2
        $x_2_3 = "Ga3GW4KubsMe0U+zINVq1pRpOrbwo16zCTJeTCsAPa5P1pVZ9HDKpyNthpACcD2iN" ascii //weight: 2
        $x_2_4 = "Fg4GpgUoOqZ9m5Ge7vhx7e2BNx8+GELNmC8bRj+yzCvRFJ4R9rP6Sj62XyRxCkFsA" ascii //weight: 2
        $x_2_5 = "L6mYLxEeCXPWWBDM954HxXPtrLam6bkDVlKyA4iDEt6szELoQFYrqXVJ4d3S3jID" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_VidarStealer_B_2147905457_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VidarStealer.B!MTB"
        threat_id = "2147905457"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VidarStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {30 04 33 46 3b f7}  //weight: 2, accuracy: High
        $x_2_2 = {8a 04 0a 8b 15 ?? ?? ?? ?? 88 04 0a 41 3b 0d}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_VidarStealer_Z_2147955452_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VidarStealer.Z!MTB"
        threat_id = "2147955452"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VidarStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {63 6d 64 20 2f 63 20 73 74 61 72 74 [0-16] 72 75 6e 64 6c 6c 33 32 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_2 = {70 6f 77 65 72 73 68 65 6c 6c [0-60] 73 74 61 72 74 2d 70 72 6f 63 65 73 73}  //weight: 1, accuracy: Low
        $x_1_3 = "/c ping localhost -n" ascii //weight: 1
        $x_1_4 = "encrypted_key" ascii //weight: 1
        $x_1_5 = "Browser Stealer" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_VidarStealer_Z_2147955452_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VidarStealer.Z!MTB"
        threat_id = "2147955452"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VidarStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Loading payload: type=%s" ascii //weight: 1
        $x_1_2 = "Injection mode selected: %s" ascii //weight: 1
        $x_1_3 = "Telegram Desktop" ascii //weight: 1
        $x_1_4 = "logins.json" ascii //weight: 1
        $x_1_5 = "Payload Loader" ascii //weight: 1
        $x_1_6 = "Crypto Reader" ascii //weight: 1
        $x_1_7 = "Monero" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_VidarStealer_Z_2147955452_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VidarStealer.Z!MTB"
        threat_id = "2147955452"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VidarStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "telegram_files" ascii //weight: 1
        $x_1_2 = "steam_files" ascii //weight: 1
        $x_1_3 = "discord_files" ascii //weight: 1
        $x_1_4 = "\\Network\\Cookies" ascii //weight: 1
        $x_1_5 = "_key.txt" ascii //weight: 1
        $x_1_6 = "*.address.txt" ascii //weight: 1
        $x_1_7 = "passwords.txt" ascii //weight: 1
        $x_1_8 = "Screenshot" ascii //weight: 1
        $x_1_9 = "Wallets" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_VidarStealer_Z_2147955452_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VidarStealer.Z!MTB"
        threat_id = "2147955452"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VidarStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "formhistory." ascii //weight: 1
        $x_1_2 = "cookies.sqlite" ascii //weight: 1
        $x_1_3 = "places.sqlite" ascii //weight: 1
        $x_1_4 = "\\IndexedDB\\chrome-extension" ascii //weight: 1
        $x_1_5 = "Login Data" ascii //weight: 1
        $x_1_6 = "All injection attempts FAILED for attempt %d" ascii //weight: 1
        $x_1_7 = "passwords.db" ascii //weight: 1
        $x_1_8 = "webdata.db" ascii //weight: 1
        $x_1_9 = "Shellcode" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_VidarStealer_RH_2147955803_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VidarStealer.RH!MTB"
        threat_id = "2147955803"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VidarStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "steamcommunity" ascii //weight: 1
        $x_1_2 = "UserName" wide //weight: 1
        $x_1_3 = "PortNumber" wide //weight: 1
        $x_1_4 = "encrypted_key" ascii //weight: 1
        $x_1_5 = "powershell" ascii //weight: 1
        $x_1_6 = "passwords.db" ascii //weight: 1
        $x_1_7 = "cookies.db" ascii //weight: 1
        $x_1_8 = "key4.db" ascii //weight: 1
        $x_1_9 = "REFLECTIVE_DLL" ascii //weight: 1
        $x_1_10 = "Injection mode selected" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_VidarStealer_RH_2147955803_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VidarStealer.RH!MTB"
        threat_id = "2147955803"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VidarStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "api.telegram.org/" ascii //weight: 2
        $x_1_2 = "screenshot" wide //weight: 1
        $x_1_3 = "Telegram Desktop\\tdata" wide //weight: 1
        $x_1_4 = "Windows\\CurrentVersion\\Run" wide //weight: 1
        $x_1_5 = "Network\\Cookies" wide //weight: 1
        $x_1_6 = "processhacker.exe" wide //weight: 1
        $x_1_7 = "\\Login Data" wide //weight: 1
        $x_1_8 = "\\places.sqlite" wide //weight: 1
        $x_1_9 = "Brave-Browser\\User Data" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_VidarStealer_ZA_2147956457_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VidarStealer.ZA!MTB"
        threat_id = "2147956457"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VidarStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "29"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "File Grabber Rules" ascii //weight: 5
        $x_5_2 = "Loader Tasks" ascii //weight: 5
        $x_1_3 = "HostName" ascii //weight: 1
        $x_1_4 = "UserName" ascii //weight: 1
        $x_1_5 = "Password" ascii //weight: 1
        $x_1_6 = "PortNumber" ascii //weight: 1
        $x_5_7 = "https://steamcommunity.com/profiles" ascii //weight: 5
        $x_5_8 = "https://telegram.me" ascii //weight: 5
        $x_5_9 = "\\IndexedDB\\chrome-extension_" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_VidarStealer_ZB_2147956458_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VidarStealer.ZB!MTB"
        threat_id = "2147956458"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VidarStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "34"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "Google\\Chrome\\User Data" ascii //weight: 10
        $x_10_2 = "BraveSoftware\\Brave-Browser\\User Data" ascii //weight: 10
        $x_10_3 = "Microsoft\\Edge\\User Data" ascii //weight: 10
        $x_1_4 = "Key decrypted successfully" ascii //weight: 1
        $x_1_5 = "Encrypted key retrieved" ascii //weight: 1
        $x_1_6 = "Found encrypted_key" ascii //weight: 1
        $x_1_7 = "Browser not detected" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

