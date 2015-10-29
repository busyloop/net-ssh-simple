# 0. test changes
# 1. commit changes
# 2. bump
# 3. make release
release:
	bundle exec yardoc
	bundle exec rake
	git commit -m 'Documentation update' doc coverage README.rdoc
	git checkout gh-pages
	git checkout master -- doc coverage
	git commit -m 'Documentation update'
	git checkout master
	git push origin gh-pages
	bundle exec rake release

