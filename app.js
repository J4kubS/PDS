/*
 * Project : TCPStats
 * Author  : Jakub Šoustar <jakub.soustar@gmail.com> <xsoust02@stud.fit.vutbr.cz>
*/

(function() {

var app = angular.module("MainApp", []),
	colors = {
		receiver: "#4C7AAF",
		sender: "#4CAF50"
	};

if (typeof TCPStats === "undefined") {
	alert("Please generate statistics first using the 'tcpstats' script!");
	return;
}

app.controller("MainController", function($scope) {
	$scope.tab = "summary";

	$scope.summary = {
		key: "summary",
		title: "Summary",
		data: TCPStats.summary
	};

	$scope.about = {
		key: "about",
		title: "About"
	};

	$scope.stats = [{
		key: "throughput",
		title: "Throughput",
		xTitle: "Time (s)",
		yTitle: "Throughput (B/s)",
		yUnit: " B/s",
		receiver: {
			title: "Throughput for " + TCPStats.throughput.receiver.ip + " → " + TCPStats.throughput.sender.ip,
			data: TCPStats.throughput.receiver.data,
			name: TCPStats.throughput.receiver.ip
		},
		sender: {
			title: "Throughput for " + TCPStats.throughput.sender.ip + " → " + TCPStats.throughput.receiver.ip,
			data: TCPStats.throughput.sender.data,
			name: TCPStats.throughput.sender.ip
		}
	}, {
		key: "sequence",
		title: "Sequence Numbers",
		xTitle: "Time (s)",
		yTitle: "Sequence Number (B)",
		yUnit: " B",
		receiver: {
			title: "Sequence Numbers for " + TCPStats.throughput.receiver.ip + " → " + TCPStats.throughput.sender.ip,
			data: TCPStats.sequence.receiver.data,
			name: TCPStats.sequence.receiver.ip,
			step: true
		},
		sender: {
			title: "Sequence Numbers for " + TCPStats.throughput.sender.ip + " → " + TCPStats.throughput.receiver.ip,
			data: TCPStats.sequence.sender.data,
			name: TCPStats.sequence.sender.ip,
			step: true
		}
	}, {
		key: "window",
		title: "Window Scaling",
		xTitle: "Time (s)",
		yTitle: "Window Size (B)",
		yUnit: " B",
		receiver: {
			title: "Window Scaling for " + TCPStats.throughput.receiver.ip + " → " + TCPStats.throughput.sender.ip,
			data: TCPStats.window.receiver.data,
			name: TCPStats.window.receiver.ip
		},
		sender: {
			title: "Window Scaling for " + TCPStats.throughput.sender.ip + " → " + TCPStats.throughput.receiver.ip,
			data: TCPStats.window.sender.data,
			name: TCPStats.window.sender.ip
		}
	}, {
		key: "rtt",
		title: "Round Trip Time",
		xTitle: "Sequence Number (B)",
		yTitle: "Round Trip Time (ms)",
		yUnit: " ms",
		receiver: {
			title: "Round Trip Time for " + TCPStats.throughput.receiver.ip + " → " + TCPStats.throughput.sender.ip,
			data: TCPStats.rtt.receiver.data,
			name: TCPStats.rtt.receiver.ip
		},
		sender: {
			title: "Round Trip Time for " + TCPStats.throughput.sender.ip + " → " + TCPStats.throughput.receiver.ip,
			data: TCPStats.rtt.sender.data,
			name: TCPStats.rtt.sender.ip
		}
	}];
});

// Based on: http://www.highcharts.com/blog/194-using-highcharts-with-angular-js
app.directive("tcpStat", function() {
	return {
		restrict: "A",
		scope: {
			options: "=",
			party: "="
		},
		link: function(scope, element) {
			var options = scope.options,
				party = scope.party,
				series;

			if (! party) {
				series = [{
					data: options["receiver"].data,
					name: options["receiver"].name,
					step: options["receiver"].step,
					color: colors["receiver"]
				}, {
					data: options["sender"].data,
					name: options["sender"].name,
					step: options["sender"].step,
					color: colors["sender"]
				}];
			} else {
				series = [{
					data: options[party].data,
					name: options[party].name,
					step: options[party].step,
					color: colors[party]
				}];
			}

			Highcharts.chart(element[0], {
				chart: {
					zoomType: "xy",
					panning: true,
					panKey: "shift"
				},
				title: {
					text: party && options[party].title || options.title
				},
				xAxis: {
					crosshair: true,
					title: {
						text: options.xTitle
					}
				},
				yAxis: {
					title: {
						text: options.yTitle
					}
				},
				tooltip: {
					valueSuffix: options.yUnit
				},
				series: series
			});
		}
	};
});

// Source: https://gist.github.com/thomseddon/3511330
app.filter("bytes", function() {
	return function(bytes, precision) {
		var units = ["B", "KiB", "MiB", "GiB", "TiB", "PiB"],
			number = Math.floor(Math.log(bytes) / Math.log(1024));

		if (bytes === 0) {
			return "0 " + units[0];
		}

		if (isNaN(parseFloat(bytes)) || ! isFinite(bytes)) {
			return "0";
		}

		if (typeof precision === 'undefined') {
			precision = 1;
		}

		return (bytes / Math.pow(1024, Math.floor(number))).toFixed(precision) +  " " + units[number];
	}
});

})();
