Usage
====

::

	python app.py [-u] -o /path/to/output.json -c /path/to/config.yaml

..

Script will gather available USN and RHSA/RHBA
advisories for packages which listed in gerrit.

Results is a formatted json in the following format:

::

	{
	'resolved': {
		'aid': {
			'cves': {
				'cid': {
					'url': 'http://vendor/specific/cve/url',
					'subject': 'CVE Subject from mitre.org',
					'references': [
						'http://link/from/mitre/references'
					],
					'commits': [
						'http://link/from/mitre/references/if/commit/in/url'
					],
				},
			},
			'packages': [
				{	'name': name,
					'dist': dist,
					'upstream_version': VERS,
					'revision': REV,
					'full_version': VERS
				}
			],
			'url': 'http://vendor/specific/advisory/url'
		}
	},
	'active': {
		'cid': {
			'dist': {
				'src_pkg_name': {
					'bug_id': bug_url
				}
			}
		}
	}
	}
..

