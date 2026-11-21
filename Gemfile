source "https://rubygems.org"

ruby file: ".ruby-version"

group :jekyll_plugins do
  gem "jekyll", "~> 4.4.1"
  gem "jekyll-feed"
  gem "jekyll-sitemap"
  gem "jekyll-redirect-from"
  gem "jekyll-paginate"
  # removed from template: jekyll-gist (embeds third-party script), jemoji (loads images from GitHub CDN)
end

gem "kramdown", ">= 2.5"
gem "kramdown-parser-gfm"
gem "webrick"

# Stdlib gems no longer bundled with Ruby 3.4+/4.x
gem "csv"
gem "base64"
gem "bigdecimal"
gem "logger"

group :development do
  gem "bundler-audit", require: false   # checks Gemfile.lock against the Ruby Advisory DB
end
