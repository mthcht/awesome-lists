rule VirTool_Win32_CoinMiner_A_2147816064_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CoinMiner.A!sms"
        threat_id = "2147816064"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CoinMiner"
        severity = "Critical"
        info = "sms: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "XMRIG_HOSTNAME" ascii //weight: 1
        $x_1_2 = "XMRIG_INCLUDE_RANDOM_MATH" ascii //weight: 1
        $x_1_3 = "donate-over-proxy" ascii //weight: 1
        $x_1_4 = "nicehash" ascii //weight: 1
        $x_1_5 = "stratum+ssl://" ascii //weight: 1
        $x_1_6 = "pool_wallet" ascii //weight: 1
        $x_1_7 = "worker_id" ascii //weight: 1
        $x_1_8 = "mining.submit" ascii //weight: 1
        $x_1_9 = "max-cpu-usage" ascii //weight: 1
        $x_1_10 = "WinRing0 driver" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CoinMiner_A_2147816072_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CoinMiner.A!!CoinMiner.A"
        threat_id = "2147816072"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CoinMiner"
        severity = "Critical"
        info = "CoinMiner: an internal category used to refer to some threats"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "XMRIG_HOSTNAME" ascii //weight: 1
        $x_1_2 = "XMRIG_INCLUDE_RANDOM_MATH" ascii //weight: 1
        $x_1_3 = "donate-over-proxy" ascii //weight: 1
        $x_1_4 = "nicehash" ascii //weight: 1
        $x_1_5 = "stratum+ssl://" ascii //weight: 1
        $x_1_6 = "pool_wallet" ascii //weight: 1
        $x_1_7 = "worker_id" ascii //weight: 1
        $x_1_8 = "mining.submit" ascii //weight: 1
        $x_1_9 = "max-cpu-usage" ascii //weight: 1
        $x_1_10 = "WinRing0 driver" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CoinMiner_B_2147829554_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CoinMiner.B!sms"
        threat_id = "2147829554"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CoinMiner"
        severity = "Critical"
        info = "sms: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2d 2d 61 6c 67 6f 3d [0-1] 72 78 2f 30}  //weight: 1, accuracy: Low
        $x_1_2 = {2d 2d 75 72 6c 3d [0-16] 2e [0-16] 2e [0-16] 3a [0-32] 2d 2d 75 73 65 72 3d}  //weight: 1, accuracy: Low
        $x_1_3 = {2d 2d 70 61 73 73 3d [0-32] 2d 2d 63 70 75 2d 6d 61 78 2d 74 68 72 65 61 64 73 2d 68 69 6e 74 3d}  //weight: 1, accuracy: Low
        $x_1_4 = "--cinit-stealth-targets=Taskmgr.exe," ascii //weight: 1
        $x_1_5 = ",procexp.exe,procexp64.exe" ascii //weight: 1
        $x_1_6 = "--cinit-api=http" ascii //weight: 1
        $x_1_7 = "--cinit-idle-wait=" ascii //weight: 1
        $x_1_8 = "--cinit-idle-cpu=" ascii //weight: 1
        $x_1_9 = "--cinit-kill-targets=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (8 of ($x*))
}

