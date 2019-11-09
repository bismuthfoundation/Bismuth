del /f /s /q dist 1>nul
rmdir /s /q dist
mkdir dist

python -m nuitka --follow-imports commands.py --windows-icon=graphics\icon.ico --standalone --show-progress -j 8 --recurse-all
python -m nuitka --follow-imports node.py --windows-icon=graphics\icon.ico --standalone --show-progress -j 8 --recurse-all
python -m nuitka --follow-imports node_stop.py --windows-icon=graphics\icon.ico --standalone --show-progress -j 8 --recurse-all

robocopy "C:\Program Files\Python37\Lib\site-packages\Cryptodome" dist\Cryptodome /MIR
robocopy "C:\Program Files\Python37\Lib\site-packages\coincurve" dist\coincurve /MIR

robocopy node.dist dist /MOVE /E
robocopy commands.dist dist /MOVE /E
robocopy node_stop.dist dist /MOVE /E

copy peers.txt dist\peers.txt
copy peers.txt dist\suggested_peers.txt
copy config.txt dist\config.txt

"C:\Program Files (x86)\Inno Setup 5\iscc" /q "setup.iss"
pause

