# -*- mode: python ; coding: utf-8 -*-

block_cipher = None


a = Analysis(['FrameScan.py'],
             pathex=['D:\\code\\Python37\\obj\\FrameScan'],
             binaries=[],
             datas=[],
             hiddenimports=['bs4','uuid','xml.etree','xml.etree.ElementTree','eventlet.hubs.epolls', 'eventlet.hubs.kqueue','eventlet.hubs.selects', 'dns','dns.asyncresolver','dns.versioned', 'dns.dnssec', 'dns.asyncquery','dns.asyncbackend','dns.e164', 'dns.hash', 'dns.namedict', 'dns.tsigkeyring', 'dns.update', 'dns.version', 'dns.zone'],
             hookspath=[''],
             runtime_hooks=[],
             excludes=[],
             win_no_prefer_redirects=False,
             win_private_assemblies=False,
             cipher=block_cipher,
             noarchive=False)
pyz = PYZ(a.pure, a.zipped_data,
             cipher=block_cipher)
exe = EXE(pyz,
          a.scripts,
          a.binaries,
          a.zipfiles,
          a.datas,
          [],
          name='FrameScan',
          debug=False,
          bootloader_ignore_signals=False,
          strip=False,
          upx=True,
          upx_exclude=[],
          runtime_tmpdir=None,
          console=True , icon='main.ico')
