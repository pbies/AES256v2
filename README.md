	AES256
	======

		https://github.com/pbies/AES256v2

		Simple AES256 file encrypter/decrypter

	Getting Started
	---------------

		1. Download the source code
		2. Run Visual Studio
		3. Open solution
		4. Build
		5. Run

	Prerequisites
	-------------

		Windows + Visual Studio

	Installing
	----------

		No need to install, runs out of the box.

	Running the tests
	-----------------

		No tests included.

	Purpose
	-------

		File encryption/decryption. No file size limit - files are streamed in 1 GiB blocks
		with a progress bar. Output format is unchanged, older .aes256 files decrypt as before.

		You may drag & drop files to buttons or click the buttons to open file dialog.

	Built With
	----------

		Visual Studio Community

	Contributing
	------------

		Edits are allowed on separate branches.

	Versioning
	----------

		When there will be new version, the old one will be overwritten.

	Notes
	-----

		FAT32 targets: encryption is refused when output would exceed 4 GiB - 1 B.

	Authors
	-------

		me - Initial work

	License
	-------

		This project is licensed under the GNU GENERAL PUBLIC LICENSE - see the
		LICENSE file for details.

		That means you must fulfill these requirements:
		1. your project have the same license
		2. you mention the original author (me)
		3. can't use scripts in commercial products if they are not free
		4. you can freely modify and use this project for personal usage

	Acknowledgments
	---------------

		If you like my work please share your opinion with me!

		pikob1 (at) gmail
