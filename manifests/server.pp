# Main ossec server config
class ossec::server (
  $mailserver_ip,
  $ossec_emailto,
  $ossec_emailfrom                     = "ossec@${::domain}",
  $ossec_active_response               = true,
  $ossec_global_host_information_level = 8,
  $ossec_global_stat_level             = 8,
  $ossec_email_alert_level             = 7,
  $ossec_ignorepaths                   = [],
  $ossec_scanpaths                     = [ {'path' => '/etc,/usr/bin,/usr/sbin', 'report_changes' => 'no', 'realtime' => 'no'}, {'path' => '/bin,/sbin', 'report_changes' => 'no', 'realtime' => 'no'} ],
  $ossec_white_list                    = [],
  $ossec_emailnotification             = 'yes',
  $ossec_package_status                = 'installed'
) {
  include ossec::common

  # install package
  case $::osfamily {
    'Debian' : {
      package { $ossec::common::hidsserverpackage:
        ensure  => $ossec_package_status,
        require => Apt::Source['alienvault-ossec'],
      }
    }
    'RedHat' : {
      case $::operatingsystem {
        'CentOS' : {
          package { 'ossec-hids':
            ensure   => $ossec_package_status,
          }
          package { $ossec::common::hidsserverpackage:
            ensure  => $ossec_package_status,
            require => Class['mysql::client'],
          }
        }
        'RedHat' : {
          package { 'ossec-hids':
            ensure   => $ossec_package_status,
          }
          package { $ossec::common::hidsserverpackage:
            ensure  => $ossec_package_status,
            require => Class['mysql::client'],
          }
        }
        default: {
          fail("Operating system not supported: ${::operatingsystem}")
        }
      }
    }
    default: { fail("OS family not supported: ${::osfamily}") }
  }

  service { $ossec::common::hidsserverservice:
    ensure    => running,
    enable    => true,
    hasstatus => $ossec::common::servicehasstatus,
    pattern   => $ossec::common::hidsserverservice,
    require   => Package[$ossec::common::hidsserverpackage],
  }

  # configure ossec
  concat { '/var/ossec/etc/ossec.conf':
    owner   => 'root',
    group   => 'ossec',
    mode    => '0440',
    require => Package[$ossec::common::hidsserverpackage],
    notify  => Service[$ossec::common::hidsserverservice]
  }
  concat::fragment { 'ossec.conf_10' :
    target  => '/var/ossec/etc/ossec.conf',
    content => template('ossec/10_ossec.conf.erb'),
    order   => 10,
    notify  => Service[$ossec::common::hidsserverservice]
  }
  concat::fragment { 'ossec.conf_90' :
    target  => '/var/ossec/etc/ossec.conf',
    content => template('ossec/90_ossec.conf.erb'),
    order   => 90,
    notify  => Service[$ossec::common::hidsserverservice]
  }

  #concat { '/var/ossec/etc/client.keys':
  #  owner   => 'root',
  #  group   => 'ossec',
  #  mode    => '0640',
  #  notify  => Service[$ossec::common::hidsserverservice],
  #  require => Package[$ossec::common::hidsserverpackage],
  #}
  #concat::fragment { 'var_ossec_etc_client.keys_end' :
  #  target  => '/var/ossec/etc/client.keys',
  #  order   => 99,
  #  content => "\n",
  #  notify  => Service[$ossec::common::hidsserverservice]
  #}
  #Ossec::Agentkey<<| |>>

}
